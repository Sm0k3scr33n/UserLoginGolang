 package main

 import (
     "net/http"
     "log"
     "fmt"
     "github.com/gorilla/mux"
     "github.com/gorilla/securecookie"
     "gopkg.in/mgo.v2"
     "gopkg.in/mgo.v2/bson"
)

type Users struct {
    //special typed semantic usage of objectid in bson format.
    //exactly mimic our database structure to include the same key values but
    //with capitol letters for whatever reason
        ID bson.ObjectId `bson:"_id,omitempty"`
        Fname string
        Lname string
        Email string
        Phone string
        Password string
}

  const indexPage = `
  <h1>Login</h1>
  <form method="post" action="/login">
      <label for="name">User name</label>
      <input type="text" id="name" name="name">
      <label for="password">Password</label>
    <input type="password" id="password" name="password">
     <button type="submit">Login</button>
 </form>
 `
 const signupPage = `
   <h1>Sign Up</h1>
   <form method="post" action="/signup">
     <label for="fname">First Name</label>
     <input type="text" id="fname" name="fname"><br>
     <label for="lname">Last Name</label>
     <input type="text" id="lname" name="lname"><br>
     <label for="email">email</label>
     <input type="text" id="email" name="email"><br>
     <label for="phone">phone number</label>
     <input type="text" id="phone" name="phone"><br>
     <label for="password">Password</label>
     <input type="password" id="password" name="password"><br>
     <label for="password">reEnter Password</label>
     <input type="password" id="password2" name="password2"><br>
     <button type="submit">Signup</button>
   </form>
  `

 const internalPage = `
 <h1>Internal</h1>
 <hr>
 <small>User: %s</small>
 <form method="post" action="/logout">
     <button type="submit">Logout</button>
 </form>
 `

const noaccessPage = `
 <h1>No access</h1>
 <hr>
 <small>sorry you do not have access</small>
  <form method="post" action="/login">
      <label for="name">User name</label>
      <input type="text" id="name" name="name">
      <label for="password">Password</label>
    <input type="password" id="password" name="password">
     <button type="submit">Login</button>
 </form>
 `

 const incorrectCredentials = `
 <h1>No access</h1>
 <hr>
 <small>sorry you entered a wrong password or username</small>
  <form method="post" action="/login">
      <label for="name">User name</label>
      <input type="text" id="name" name="name">
      <label for="password">Password</label>
    <input type="password" id="password" name="password">
     <button type="submit">Login</button>
 </form>
 `

 func PageHandler404(response http.ResponseWriter, request *http.Request) {
     const error404 = `
     <h1>4XX error so you've been 307'd to a Page expressing our appologies</h1>
     `
     fmt.Fprintf(response, error404)
 }

 func indexPageHandler(response http.ResponseWriter, request *http.Request) {
     fmt.Fprintf(response, indexPage)
 }

///I believe we use the internalPageHandler for template generation usage as well
 func internalPageHandler(response http.ResponseWriter, request *http.Request) {
     userName := getUserName(request)
     //if username is nil redirect temp to the main index handler
     if userName != "" {
         fmt.Fprintf(response, internalPage, userName)
     } else {
         http.Redirect(response, request, "/noaccess", 302)
     }
 }

 func noAccesHandler(response http.ResponseWriter, request *http.Request) {
         fmt.Fprintf(response, noaccessPage)
 }

 func badCredentials(response http.ResponseWriter, request *http.Request) {
         fmt.Fprintf(response, incorrectCredentials)
 }

 var cookieHandler = securecookie.New(
     securecookie.GenerateRandomKey(64),
     securecookie.GenerateRandomKey(32))

  func loginHandler(response http.ResponseWriter, request *http.Request) {
      name := request.FormValue("name")
      pass := request.FormValue("password")
      redirectTarget := "/"
      if name != "" && pass != "" {
        // .. check credentials ..
        session, err := mgo.Dial("localhost")
        if err != nil {
                panic(err)
        }
        defer session.Close()
        session.SetMode(mgo.Monotonic, true)
        /// we have a db called 'site-users' with a 'collection' called users
        c := session.DB("site-users").C("users")
        ///define a variable as the type struct Users
        result := Users{}
        ///so long as the error is not nil from the query, we get back the password from the result
        err = c.Find(bson.M{"email": name}).One(&result)
        //err := c.Update(bson.M{"password": newPass}, update)

        ///we check our database results against the entered value from the user
        ///since we only create a session when the password in the database checks we therefore restrict the usage of sessions

	if pass==result.Password{
		///we need to add session handling in addition to the usage of cookies
         log.Println("Password good")
         log.Println(result.ID, result.Fname, result.Lname, result.Email, result.Password, result.Phone)
         log.Println("entered password", pass)
         setSession(name, response)
         redirectTarget = "/internal"
	}else{
		 log.Println("Password or username incorrect")
         //
         log.Println(result.ID, result.Fname, result.Lname, result.Email, result.Password, result.Phone)
         log.Println("entered password", pass)
		 http.Redirect(response, request, "/badCredentials", 302)
	}
      }
      ///I think it should be 307 redirect for a "temporary" redirect
     http.Redirect(response, request, redirectTarget, 302)
 }

  func signup(response http.ResponseWriter, request *http.Request) {
         fmt.Fprintf(response, signupPage)
 }

func signupHandler(response http.ResponseWriter, request *http.Request){
    fname := request.FormValue("fname")
    lname := request.FormValue("lname")
    email := request.FormValue("email")
    phone := request.FormValue("phone")
    password := request.FormValue("password")
    fmt.Fprintf(response, "you submitted something" + fname + " " + lname + " " + email + " " + phone + " " + password)
    // Set up authentication information.
    sender := NewSender("email@example.com", "password")
	//The receiver needs to be in slice as the receive supports multiple receiver
    //eventually this should reflect a passed variable when the user signs up
	Receiver := []string{ "email@example2.com", "email@example.com"}
	Subject := "Sign up successfully completed. Thank you."
	bodyMessage := "Sending email using Golang. Yeah\n\n" + fname + " " + lname + " " + email + " " + phone + " " + password
	sender.SendMail(Receiver, Subject, bodyMessage)

}

 func logoutHandler(response http.ResponseWriter, request *http.Request) {
     clearSession(response)
     http.Redirect(response, request, "/", 302)
 }

//here we set the session key with a cookie and we set the session variables
//on the server using the gorilla mux
 func setSession(userName string, response http.ResponseWriter) {
      value := map[string]string{
          "name": userName,
      }
      if encoded, err := cookieHandler.Encode("session", value); err == nil {
          cookie := &http.Cookie{
              Name:  "session",
              Value: encoded,
              Path:  "/",
         }
         http.SetCookie(response, cookie)
     }
 }


 func getUserName(request *http.Request) (userName string) {
     if cookie, err := request.Cookie("session"); err == nil {
         cookieValue := make(map[string]string)
         if err = cookieHandler.Decode("session", cookie.Value, &cookieValue); err == nil {
             userName = cookieValue["name"]
         }
     }
     return userName
 }

//we want to reset the session cookie by simple makin git blank on the client
// and clear the session on the server with the session.clear function
 func clearSession(response http.ResponseWriter) {
     cookie := &http.Cookie{
         Name:   "session",
         Value:  "",
         Path:   "/",
         MaxAge: -1,
     }
     http.SetCookie(response, cookie)
 }

/// create a router with the gorilla mux router and handle the requests
var router = mux.NewRouter()
func main() {
     router.NotFoundHandler = http.HandlerFunc(PageHandler404)
	 ///handlers for the gorilla mux router
     router.HandleFunc("/", indexPageHandler)
     router.HandleFunc("/internal", internalPageHandler)
     router.HandleFunc("/noaccess", noAccesHandler)
     router.HandleFunc("/badCredentials", badCredentials)
     router.HandleFunc("/signup-page", signup)
     ///router.HandleFunc("/signup", signupAction)
     ///router.HandleFunc("", )
     ///router.HandleFunc("/resetPassword", resetPasswordHandler).Methods.("POST")
     router.HandleFunc("/signup", signupHandler).Methods("POST")
     router.HandleFunc("/login", loginHandler).Methods("POST")
     router.HandleFunc("/logout", logoutHandler).Methods("POST")
     http.Handle("/", router)
     http.ListenAndServeTLS(":8000", "server.crt", "server.key", nil)
 }
