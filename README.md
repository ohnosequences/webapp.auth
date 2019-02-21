# webapp.auth
Utilities for login, logout, password change and session management in webapps backends in Scala Play.

## Installation

In a Scala Play project, you should add this to your dependencies:

```scala
resolvers += "Era7 maven releases" at "https://s3-eu-west-1.amazonaws.com/releases.era7.com"
libraryDependencies += "ohnosequences" %% "webapp.auth" % "x.y.z"
```

where `x.y.z` is the version of the [latest release](https://github.com/ohnosequences/webapp.auth/releases/latest)


## Use

This package is intended to be used with [PostgreSQL](https://www.postgresql.org) and [PostgREST](http://postgrest.org) as database system.

### Previous configuration

The database should have tables to store users and their sessions with the following minimal fields:

```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password BYTEA NOT NULL
);


CREATE TABLE sessions (
    id INTEGER REFERENCES users(id),
    token BYTEA NOT NULL,
    expires TIMESTAMP NOT NULL,
    valid BOOLEAN NOT NULL DEFAULT TRUE
);
```

Apart from that, Scala Play should include the following configuration in `conf/application.conf` file:

```
play.http.session {
  cookieName = "MY_SESSION_COOKIE"
  httpOnly = false
  # 2 hours for max age of session, in milliseconds
  maxAge = 7200000
  # TODO This should be set to true when if our site has https
  secure = false
  sameSite = "lax"
}
```

### Abstract classes

This package includes:

#### An abstract `Login` controller

It has two abstract fields: 

* `usersTable` which should point, when extended, to the endpoint of PostgREST corresponding to the 
users table: for example `https://localhost:3000/users`
* `sessionsTable` which should point, when extended, to the endpoint of PostgREST corresponding to 
the sessions table: for example `https://localhost:3000/sessions`

This controller contains code to perform the login and logout action of an user with two methods:

* `login`
* `logout`

Following arguments for `login` should be passed in the body:

* `email`
* `password`

Password should be sent in plain text using HTTPs in the client.

When an user performs his/her logout, the token is marked as `valid = False` in the database, and the cookie gets erased from the client.

We DO NOT reuse tokens. That means that every time an user logins, a new token gets assigned to him/her.

Tokens are randomly generated with a length of 128 bytes.

#### An abstract `Authenticated` action builder

That class should be extended because it contains a `sessionsTable` abstract value, that should point to the same endpoint the `Login` class points to (e.g. `https://localhost:3000/sessions`).

Imagine we have code to do something once the user has identified himself/herself:

```scala
import javax.inject._
import play.api.mvc.Results._

class MyController @Inject (...) {
    
    doAction: Result = Action { request =>
       // parse the request for parameters and do actual stuff with it
       ...
    }
    
    doAsyncAction: Future[Result] = Action.async { request =>
       // parse the request for parameters and do actual stuff with it
       ...
    }
}
```

Then to restrict those actions to authenticated requests (those which carry a valid token) we should 
inject an instance of `Authenticated`, for example `authenticated: Authenticated` and substitute `Action` for `authenticated`:

```scala
import javax.inject._
import play.api.mvc.Results._

class MyController @Inject (..., authenticated: Authenticated) {
    
    doAction: Result = authenticated { request =>
       // parse the request for parameters and do actual stuff with it
       ...
    }
    
    doAsyncAction: Future[Result] = authenticated.async { request =>
       // parse the request for parameters and do actual stuff with it
       ...
    }
}
```

If the authentication fails, or the token is expired, a `Results.Unauthorized` instance is thrown (HTTP code 401). That's it, we do not have to worry about checking the credentials ourselves, the authenticated action does it for us, and if they are correct, then the code included among `{ }` is executed.

#### An abstract `PasswordChange` controller

This controller is abstract because it includes a value `usersTable` which should point to the users table when the class is extended (e.g. `https://localhost:3000/users`). It contains a `changePassword` method which receives the current password, the new password and the new password repeated in the following body fields, respectively:

* `current`
* `new`
* `renew`

Those fields should be transmited in plain text using HTTPs.

#### An auxiliary object `Auth`

Interesting thing about this `Auth` object is that it could be used to hash passwords and introduce them, by hand, in the database:

```scala
import webapp.auth.Auth

Auth.password.hash("pass")
//24372443362e2e2e2e2f2e2e2e2e3774554b6631657252587931706f5469646c76757a4d74526a7949797058423972364a537a6944495061332470394c537a74316b496e454b52583333435453626d462e30664f4f2f706a64503141435636514c2f78633200
```

To introduce them in the database:

```sql
psql

INSERT INTO
       users ( email, password )
       VALUES ( 'user@era7.com', '\x24372443362e2e2e2e2f2e2e2e2e3774554b6631657252587931706f5469646c76757a4d74526a7949797058423972364a537a6944495061332470394c537a74316b496e454b52583333435453626d462e30664f4f2f706a64503141435636514c2f78633200');

```

Note the initial `\x` marker when introducing it in the database, because this data is encoded in hexadecimal.

## Examples

This is an example coming from a real project.

### `app/controllers/db.scala` file
```scala
package controllers

import javax.inject._
import play.api.libs.ws.{WSClient}
import scala.concurrent.{ExecutionContext}
import play.api.Configuration
import webapp.db.postgrest.Database

class Database @Inject()(val ws: WSClient, val configuration: Configuration)(
    implicit val ec: ExecutionContext,
    implicit val materializer: akka.stream.Materializer) {

  private val host = configuration.get[String]("db.url")

  implicit val token = configuration.get[String]("db.token")

  implicit val wsClient = ws

  val users                = Database.Endpoint(host + "/users")
  val sessions             = Database.Endpoint(host + "/sessions")
  val projects             = Database.Endpoint(host + "/projects")
  val datasets             = Database.Endpoint(host + "/datasets")
  val files                = Database.Endpoint(host + "/files")
  val datasetFiles         = Database.Endpoint(host + "/files_in_dataset")
  val projectDatasets      = Database.Endpoint(host + "/datasets_in_project")
  val projectAnalyses      = Database.Endpoint(host + "/project_analyses")
  val datasetAnalyses      = Database.Endpoint(host + "/dataset_analyses")
  val projectAnalysisOwner = Database.Endpoint(host + "/project_analysis_owner")
}
```

### `app/controllers/auth.scala` file

```scala
package controllers

import javax.inject._
import play.api.mvc.{BodyParsers, ControllerComponents}
import play.api.Configuration
import scala.concurrent.ExecutionContext

class Auth @Inject()(cc: ControllerComponents,
                     authenticated: Authenticated,
                     db: Database,
                     configuration: Configuration)(
    implicit override val ec: ExecutionContext
) extends webapp.auth.Login(cc, authenticated, ws) {

  val usersTable = db.users

  val sessionsTable = db.sessions

  val sessionMaxAge = configuration.get[Long]("play.http.session.maxAge")
}

class Authenticated @Inject()(parser: BodyParsers.Default, db: Database)(
      implicit executionContext: ExecutionContext
  ) extends webapp.auth.Authenticated(parser) {

    val sessionsTable = db.sessions
}
```

### `app/controllers/settings.scala` file

```scala
package controllers

import javax.inject._
import play.api.mvc._
import scala.concurrent.{ExecutionContext, Future}

class Settings @Inject()(
    cc: ControllerComponents,
    authenticated: Authenticated,
    val db: Database
)(implicit ec: ExecutionContext)
    extends webapp.auth.PasswordChange(cc, authenticated) {

  val usersTable = db.users
}
```

### `conf/routes` file

```
# Login
POST    /login                      controllers.Auth.login

GET     /logout                     controllers.Auth.logout

# Settings
POST    /settings/password          controllers.Settings.changePassword
```
