package webapp.auth

import play.api.mvc._
import play.api.mvc.Results._
import play.api.libs.ws._
import play.api.libs.json._
import scala.concurrent.{ExecutionContext, Future}

abstract class PasswordChange(val cc: ControllerComponents,
                              val authenticated: Authenticated,
                              val ws: WSClient)(
    implicit val ec: ExecutionContext
) extends AbstractController(cc) {

  val usersTable: String

  def changePassword = authenticated.async { request =>
    val currentPassword = request.body.asFormUrlEncoded.get("current").head
    val newPassword     = request.body.asFormUrlEncoded.get("new").head
    val reNewPassword   = request.body.asFormUrlEncoded.get("new").head
    val id              = request.user
    val badRequest      = Future.successful { Results.BadRequest: Result }

    if (newPassword != currentPassword) {
      if (newPassword == reNewPassword && !newPassword.isEmpty) {
        val wsrequest = ws.url(
          usersTable +
            "?id=eq." + id
        )

        wsrequest.get.flatMap { response =>
          val usersArray = response.json.as[JsArray].value

          // Get users that match the input password
          val maybeCorrectPass = usersArray.collectFirst {
            /*
             Convert the field password to an String and
             check whether it matches the encryption of
             the password from the database
             */
            case user if (user("password").asOpt[String].fold(false) { hashed =>
                  Auth.password.verify(hashed.stripPrefix("\\x"),
                                       currentPassword)
                }) =>
              user
          }

          maybeCorrectPass.fold(badRequest) { _ =>
            val passInfo: JsValue = Json.obj(
              "password" -> ("\\x" ++ Auth.password.hash(newPassword))
            )

            wsrequest.patch(passInfo).map { _ =>
              Results.Ok: Result
            }
          }
        }
      } else {
        badRequest
      }
    } else {
      badRequest
    }
  }
}
