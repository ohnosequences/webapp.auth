package webapp.auth

import play.api.mvc._
import play.api.mvc.Results._
import play.api.libs.ws._
import play.api.libs.json._
import scala.concurrent.{ExecutionContext, Future}
import org.abstractj.kalium
import kalium.NaCl.Sodium
import kalium.encoders.Encoder.HEX
import java.sql.Timestamp
import java.net.URLEncoder

object HttpRequest {

  @inline def escapeParameter(parameter: String): String =
    URLEncoder.encode(parameter, "UTF-8")
}

abstract class Login(val cc: ControllerComponents,
                     val authenticated: Authenticated,
                     val ws: WSClient)(
    implicit val ec: ExecutionContext
) extends AbstractController(cc) {

  val usersTable: String

  val sessionsTable: String

  def login = Action.async { request =>
    //TODO: Add token generation + TLS
    val inputUser     = request.body.asFormUrlEncoded.get("email").head
    val inputPassword = request.body.asFormUrlEncoded.get("pass").head
    val sessionMaxAge =
      play.Play.application.configuration
        .getLong("play.http.session.maxAge")

    // Query for the database
    val wsrequest: WSRequest =
      ws.url(
        usersTable +
          "?email=eq." + HttpRequest.escapeParameter(inputUser)
      )

    wsrequest.get.flatMap { response =>
      val usersArray = response.json.as[JsArray].value

      // Get users that match the input password
      val maybeAuthorizedUser = usersArray.collectFirst {
        /*
         Convert the field password to an String and
         check whether it matches the encryption of
         the password from the database
         */
        case user
            if (
              user("password").asOpt[String].fold(false) { hashed =>
                Auth.password.verify(hashed.stripPrefix("\\x"), inputPassword)
              }
            ) =>
          user.as[JsObject]
      }

      // If user credentials are correct, generate session
      // token tied to its id, post it to the database, and
      // return 200 with a session cookie, else return unauthorized (401)
      maybeAuthorizedUser.fold(
        Future.successful { Results.Unauthorized: Result }
      ) { result =>
        val userID       = result("id").as[Int].toString
        val sessionToken = Auth.createToken
        val expiration   = new Timestamp(System.currentTimeMillis)
        expiration.setTime(expiration.getTime + sessionMaxAge)

        val session: JsValue = Json.obj(
          "id"      -> userID,
          "token"   -> s"\\x${sessionToken}",
          "expires" -> expiration.toString
        )

        // TODO. Should this be checked for failures? if successes,
        // it returns a 201
        ws.url(sessionsTable).post(session).map { response =>
          Results.Ok
            .withSession(
              "id"    -> userID,
              "token" -> sessionToken
            )
        }
      }
    }
  }

  def logout = authenticated.async { request =>
    val session = request.session
    val closeSession: Future[Result] = Future.successful {
      Results.Ok.withNewSession
    }

    session.get("id").fold(closeSession) { id =>
      session.get("token").fold(closeSession) { token =>
        val wsrequest: WSRequest = ws.url(
          sessionsTable + "?" +
            "id=eq." + id +
            "&" +
            "token=eq." + s"\\x${token}'"
        )

        val session: JsValue = Json.obj(
          "valid" -> false
        )

        wsrequest.patch(session).flatMap { _ =>
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

  def checkValidToken(sessionsTable: String, ws: WSClient)(
      id: UserID,
      token: Token)(implicit ec: ExecutionContext): Future[Boolean] = {

    val wsrequest = ws.url(
      sessionsTable +
        "?id=eq." +
        HttpRequest.escapeParameter(id)
    )

    wsrequest.get.map { response =>
      val sessions = response.json.as[JsArray].value

      // We need to append a \x prefix to the token, since
      // that is the way postgresql stores hex strings
      val maybeAuthorizedSession = sessions.collectFirst {
        case session
            if (
              session("id").as[Int].toString == id &&
                session("token").as[String] == ("\\x" ++ token)
            ) => {
          /* Postgrest replaces " " in timestamps for a T, according to ISO-8601
             Example: "2019-01-25 19:16:59.281" is returned as "2019-01-25T19:16:59.281"

             https://github.com/PostgREST/postgrest/issues/177
           */
          val expiration =
            Timestamp.valueOf(session("expires").as[String].replace("T", " "))
          val currentTime = new Timestamp(System.currentTimeMillis)

          currentTime.before(expiration)
        }
      }

      maybeAuthorizedSession.fold(false) { authorized =>
        authorized
      }
    }
  }
}

// https://www.playframework.com/documentation/2.6.x/ScalaActionsComposition#Action-composition
case class AuthenticatedRequest[A](val user: String, request: Request[A])
    extends WrappedRequest[A](request)

abstract class Authenticated(val parser: BodyParsers.Default, val ws: WSClient)(
    implicit val executionContext: ExecutionContext
) extends ActionBuilder[AuthenticatedRequest, AnyContent] {

  val sessionsTable: String

  private val checkValidToken = Auth.checkValidToken(sessionsTable, ws) _

  private val unauthorized: Future[Result] = Future.successful { Unauthorized }

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
