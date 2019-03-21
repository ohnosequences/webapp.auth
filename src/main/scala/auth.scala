package webapp.auth

import play.api.mvc._
import play.api.mvc.Results._
import play.api.libs.ws._
import play.api.libs.json._
import webapp.db.postgrest.Database, Database.{Predicate => Pred}
import scala.concurrent.{ExecutionContext, Future}
import org.abstractj.kalium
import kalium.NaCl.Sodium
import kalium.encoders.Encoder.HEX
import java.sql.Timestamp

abstract class Login(val cc: ControllerComponents,
                     val authenticated: Authenticated,
                     val ws: WSClient)(
    implicit val ec: ExecutionContext
) extends AbstractController(cc) {

  val usersTable: Database.Endpoint

  val sessionsTable: Database.Endpoint

  val sessionMaxAge: Long

  val unauthorized: Result = Unauthorized("Incorrect user or password")

  def login = Action.async { request =>
    val form = request.body.asFormUrlEncoded
    val absentParams = Future.successful {
      BadRequest("Form parameters cannot be absent")
    }

    form.fold(absentParams) { form =>
      form.get("email").fold(absentParams) {
        _.headOption.fold(absentParams) { inputUser =>
          form.get("pass").fold(absentParams) {
            _.headOption.fold(absentParams) { inputPassword =>
              if (inputUser.isEmpty || inputPassword.isEmpty) {
                absentParams
              } else {

                usersTable.select
                  .columns("id", "password")
                  .singular
                  .where(
                    Pred.eq("email", inputUser)
                  )
                  .onFailure { _ =>
                    unauthorized
                  }
                  .onSuccess { response =>
                    val user = response.json.as[JsObject]
                    /*
                     Convert the field password to an String and
                     check whether it matches the encryption of
                     the password from the database
                     */
                    val hashedPass = user("password").as[String]
                    val authorized =
                      Auth.password.verify(hashedPass.stripPrefix("\\x"),
                                           inputPassword)

                    // If user credentials are correct, generate session
                    // token tied to its id, post it to the database, and
                    // return 200 with a session cookie, else return unauthorized (401)
                    if (authorized) {
                      val userID       = user("id").as[Int].toString
                      val sessionToken = Auth.createToken
                      val expiration   = new Timestamp(System.currentTimeMillis)
                      expiration.setTime(expiration.getTime + sessionMaxAge)

                      sessionsTable
                        .insert(
                          "id"      -> userID,
                          "token"   -> s"\\x${sessionToken}",
                          "expires" -> expiration.toString
                        )
                        .onFailure { _ =>
                          Unauthorized(
                            "An error occurred while creating a valid session")
                        }
                        .failIfAlreadyExists
                        .onSuccess { _ =>
                          Ok("You logged in successfully!").withSession(
                            "id"    -> userID,
                            "token" -> sessionToken
                          )
                        }
                    } else {
                      Future.successful { unauthorized }
                    }
                  }
              }
            }
          }
        }
      }
    }
  }

  def logout = authenticated.async { request =>
    val session = request.session
    val closeSession = Future.successful {
      Ok("You logged out successfully!").withNewSession
    }

    session.get("id").fold(closeSession) { id: String =>
      session.get("token").fold(closeSession) { token: String =>
        sessionsTable
          .update(
            "valid" -> false
          )
          .where(
            Pred.eq("id", id),
            Pred.eq("token", s"\\x${token}")
          )
          // We want to clear the cookie from the user's session no matter
          // if setting the session as invalid fails or not
          .onFailure { _ =>
            closeSession
          }
          .onSuccess { _ =>
            closeSession
          }
      }
    }
  }

}

object Auth {
  type UserID = String
  type Token  = String

  // Object to hash and verify the passwords
  object password {
    private val opslimit =
      Sodium.CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE

    private val memlimit =
      Sodium.CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE

    private val cryptoGen = new kalium.crypto.Password

    private val encoder = kalium.encoders.Encoder.HEX

    def hash(pass: String): String =
      cryptoGen.hash(pass.getBytes, encoder, opslimit, memlimit)

    def verify(hashed: String, pass: String): Boolean =
      cryptoGen.verify(HEX.decode(hashed), pass.getBytes)
  }

  val random = new kalium.crypto.Random()

  val tokenLength: Int = 128;

  def createToken: String = {
    val bytes = random.randomBytes(tokenLength)
    val token = HEX.encode(bytes)

    token
  }

  def checkValidToken(sessionsTable: Database.Endpoint)(
      id: UserID,
      token: Token): Future[Boolean] =
    sessionsTable.select
      .columns("expires")
      .where(
        Pred.eq("id", id),
        // We need to append a \x prefix to the token, since
        // that is the way postgresql stores hex strings
        Pred.eq("token", "\\x" ++ token)
      )
      .onFailure { _ =>
        false
      }
      .onSuccess { response =>
        val sessions = response.json.as[JsArray].value

        // We need to append a \x prefix to the token, since
        // that is the way postgresql stores hex strings
        val maybeAuthorizedSession = sessions.collectFirst {
          case session: JsObject =>
            /* Postgrest replaces " " in timestamps for a T, according to ISO-8601
           Example: "2019-01-25 19:16:59.281" is returned as "2019-01-25T19:16:59.281"
           https://github.com/PostgREST/postgrest/issues/177
             */
            val expiration =
              Timestamp.valueOf(session("expires").as[String].replace("T", " "))
            val currentTime = new Timestamp(System.currentTimeMillis)

            currentTime.before(expiration)
        }

        maybeAuthorizedSession.fold(false) { authorized =>
          authorized
        }
      }
}

// https://www.playframework.com/documentation/2.6.x/ScalaActionsComposition#Action-composition
case class AuthenticatedRequest[A](val user: String, request: Request[A])
    extends WrappedRequest[A](request)

abstract class Authenticated(val parser: BodyParsers.Default)(
    implicit val executionContext: ExecutionContext
) extends ActionBuilder[AuthenticatedRequest, AnyContent] {

  val sessionsTable: Database.Endpoint

  private val checkValidToken = Auth.checkValidToken(sessionsTable) _

  private val unauthorized: Future[Result] = Future.successful {
    Unauthorized("Not valid credentials")
  }

  def invokeBlock[A](
      request: Request[A],
      handler: AuthenticatedRequest[A] => Future[Result]
  ) = {
    val session = request.session

    // If the token or the user ID are not present,
    // return unauthorized
    session.get("id").fold(unauthorized) { userID =>
      session.get("token").fold(unauthorized) { token =>
        // We need to search for user and pass in the
        // database and check that they are correct
        checkValidToken(userID, token).flatMap { valid =>
          if (valid)
            handler(AuthenticatedRequest(userID, request))
          else
            unauthorized
        }
      }
    }
  }
}
