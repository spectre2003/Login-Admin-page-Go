package main

import (
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type User struct {
	Id       uint   `gorm:"primaryKey"`
	Name     string `gorm:"unique;size:20"`
	Email    string `gorm:"size:50"`
	Password string `gorm:"size:20"`
}

type Admin struct {
	Id       uint   `gorm:"primaryKey"`
	Name     string `gorm:"size:50"`
	Password string `gorm:"size:20"`
}

type userDisply []struct {
	Name  string
	Email string
}

var jwtSecret = []byte("123456")

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

var db *gorm.DB

func initDB() {
	dsn := "host=localhost user=postgres password=password dbname=login_page"
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("failed to connect to database")
	}
	db.AutoMigrate(&User{})
	db.AutoMigrate(&Admin{})
}

func main() {

	initDB()

	fs := http.FileServer(http.Dir("./web/static"))
	http.Handle("/web/static/", http.StripPrefix("/web/static/", fs))

	http.HandleFunc("/", loginPageHandler)
	http.HandleFunc("/signup", signupPageHandler)
	http.HandleFunc("/admin-login", adminLoginHandler)
	http.HandleFunc("/update-user", userUpdate)
	http.HandleFunc("/delete-user", userDelete)
	http.HandleFunc("/home", homePageHandler)
	http.HandleFunc("/admin-panel", adminPanelHandler)
	http.HandleFunc("/addUser", addUser)
	http.HandleFunc("/search", searchHandler)
	http.HandleFunc("/signout", signoutHandler)
	http.HandleFunc("/admin-signout", adminSignoutHandler)

	http.ListenAndServe(":8080", nil)
}

func addNoCacheHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
}

func adminPanelHandler(w http.ResponseWriter, r *http.Request) {
	addNoCacheHeaders(w)
	cookie, err := r.Cookie("token")
	if err != nil {
		http.Redirect(w, r, "/admin-login", http.StatusSeeOther)
		return
	}

	token, err := jwt.ParseWithClaims(cookie.Value, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		http.Redirect(w, r, "/admin-login", http.StatusSeeOther)
		return
	}

	var user userDisply
	result := db.Model(&User{}).Select("name,email").Find(&user)
	if result.Error != nil {
		http.Error(w, "cant get the users"+result.Error.Error(), http.StatusBadRequest)
		return
	}

	tmpl := template.Must(template.ParseFiles("./web/templates/admin_dashboard.html"))
	tmpl.Execute(w, user)

}
func userUpdate(w http.ResponseWriter, r *http.Request) {
	addNoCacheHeaders(w)
	if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "unable to parse form", http.StatusBadRequest)
			return
		}

		currentUsername := r.FormValue("currentUsername") // This must match the hidden input field name
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		//fmt.Println("Current Username:", currentUsername)

		var user User
		result := db.Where("name = ?", currentUsername).First(&user)
		if result.Error != nil {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		user.Name = username
		user.Email = email
		if password != "" {
			user.Password = password // Only update password if it's provided
		}

		result = db.Save(&user)
		if result.Error != nil {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Account Created</title>
            </head>
            <body>
                <script>
                    alert('Username is already taken');
                    window.location.href = '/admin-panel'; // Redirect to login page
                </script>
            </body>
            </html>
        `)
		}
		http.Redirect(w, r, "/admin-panel", http.StatusSeeOther)
	}
}

func userDelete(w http.ResponseWriter, r *http.Request) {
	addNoCacheHeaders(w)
	if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "unable to parse form", http.StatusBadRequest)
			return
		}

		currentUsername := r.FormValue("currentName")

		var user User
		result := db.Where("name = ?", currentUsername).Delete(&user)
		if result.Error != nil {
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}

		http.Redirect(w, r, "/admin-panel", http.StatusSeeOther)
	}
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
	addNoCacheHeaders(w)
	if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}
		name := r.FormValue("searchUser")

		var users []User
		result := db.Where("name LIKE ?", "%"+name+"%").Find(&users)

		if result.Error != nil {
			http.Error(w, "Unable to perform search: "+result.Error.Error(), http.StatusBadRequest)
			return
		}
		tmpl := template.Must(template.ParseFiles("./web/templates/admin_dashboard.html"))
		tmpl.Execute(w, users)
	}
}

func loginPageHandler(w http.ResponseWriter, r *http.Request) {
	addNoCacheHeaders(w)

	cookie, err := r.Cookie("token")
	if err == nil {
		token, err := jwt.ParseWithClaims(cookie.Value, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err == nil && token.Valid {
			http.Redirect(w, r, "/home", http.StatusSeeOther)
			return
		}
	}

	if r.Method == "GET" {
		//addNoCacheHeaders(w)
		tmpl := template.Must(template.ParseFiles("./web/templates/login.html"))
		tmpl.Execute(w, nil)
	} else if r.Method == "POST" {
		//addNoCacheHeaders(w)
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")

		var user User
		result := db.Where("name=? AND password=?", username, password).First(&user)
		if result.Error != nil {
			tmpl := template.Must(template.ParseFiles("./web/templates/login.html"))
			tmpl.Execute(w, map[string]string{"Error": "Invalid username or password"})
			// http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			// return
		}

		// If user is found and credentials are correct, generate a JWT token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
			Username: username,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(time.Hour * 170).Unix(),
			},
		})

		tokenString, err := token.SignedString(jwtSecret)
		if err != nil {
			http.Error(w, "Could not create token", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "token",
			Value:    tokenString,
			Expires:  time.Now().Add(time.Hour * 170),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
		addNoCacheHeaders(w)

		// Redirect to the home page
		http.Redirect(w, r, "/home", http.StatusSeeOther)
	}
}
func signupPageHandler(w http.ResponseWriter, r *http.Request) {
	addNoCacheHeaders(w)

	cookie, err := r.Cookie("token")
	if err == nil {
		token, err := jwt.ParseWithClaims(cookie.Value, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err == nil && token.Valid {
			http.Redirect(w, r, "/home", http.StatusSeeOther)
			return
		}
	}

	if r.Method == "GET" {
		tmpl := template.Must(template.ParseFiles("./web/templates/signup.html"))
		tmpl.Execute(w, nil)
	} else if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		user := User{Name: username, Email: email, Password: password}

		result := db.Create(&user)

		if result.Error != nil {
			tmpl := template.Must(template.ParseFiles("./web/templates/signup.html"))
			tmpl.Execute(w, map[string]string{"Error": "Username is already taken"})
			return
		}

		// Generate JWT token after signup
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
			Username: username,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(time.Hour * 170).Unix(),
			},
		})

		tokenString, err := token.SignedString(jwtSecret)
		if err != nil {
			http.Error(w, "Could not create token", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "token",
			Value:    tokenString,
			Expires:  time.Now().Add(time.Hour * 170),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})

		// Redirect to the home page after successful signup
		http.Redirect(w, r, "/home", http.StatusSeeOther)
	}
}

func addUser(w http.ResponseWriter, r *http.Request) {
	addNoCacheHeaders(w)
	if r.Method == "POST" {
		addNoCacheHeaders(w)
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")

		user := User{Name: username, Email: email, Password: password}

		result := db.Create(&user)

		if result.Error != nil {
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Account Created</title>
            </head>
            <body>
                <script>
                    alert('Username is already taken');
                    window.location.href = '/admin-panel';
                </script>
            </body>
            </html>
        `)
		}

		http.Redirect(w, r, "/admin-panel", http.StatusSeeOther)

		fmt.Printf("Received username: %s, password: %s, email: %s\n", username, password, email)
	}
}

func adminLoginHandler(w http.ResponseWriter, r *http.Request) {
	addNoCacheHeaders(w)
	cookie, err := r.Cookie("token")
	if err == nil {
		token, err := jwt.ParseWithClaims(cookie.Value, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err == nil && token.Valid {
			http.Redirect(w, r, "/admin-panel", http.StatusSeeOther)
			return
		}
	}
	if r.Method == "GET" {
		tmpl := template.Must(template.ParseFiles("./web/templates/admin_login.html"))
		tmpl.Execute(w, nil)
	} else if r.Method == "POST" {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Unable to parse form", http.StatusBadRequest)
			return
		}

		adminName := r.FormValue("adminName")
		password := r.FormValue("password")

		var admin Admin

		result := db.Where("name=? AND password=?", adminName, password).First(&admin)
		if result.Error != nil {
			tmpl := template.Must(template.ParseFiles("./web/templates/admin_login.html"))
			tmpl.Execute(w, map[string]string{"Error": "Invalid username or password"})
			//http.Error(w, "faild "+result.Error.Error(), http.StatusBadRequest)
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
			Username: adminName,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(time.Hour * 170).Unix(),
			},
		})

		tokenString, err := token.SignedString(jwtSecret)
		if err != nil {
			http.Error(w, "Could not create token", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "token",
			Value:    tokenString,
			Expires:  time.Now().Add(time.Hour * 170),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})

		addNoCacheHeaders(w)
		http.Redirect(w, r, "/admin-panel", http.StatusSeeOther)

		fmt.Printf("Received adminName: %s, password: %s\n", adminName, password)
	}
}

func homePageHandler(w http.ResponseWriter, r *http.Request) {
	addNoCacheHeaders(w)
	cookie, err := r.Cookie("token")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	token, err := jwt.ParseWithClaims(cookie.Value, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || token.Valid == false {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	username := claims.Username

	addNoCacheHeaders(w)
	tmpl := template.Must(template.ParseFiles("./web/templates/home.html"))
	tmpl.Execute(w, map[string]string{"Username": username})
}
func signoutHandler(w http.ResponseWriter, r *http.Request) {
	addNoCacheHeaders(w)
	if r.Method == "POST" {
		// Invalidate the token by setting the cookie's expiration date to the past
		http.SetCookie(w, &http.Cookie{
			Name:     "token",
			Value:    "",
			Expires:  time.Now().Add(-time.Hour),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
		// Redirect to the login page
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}
func adminSignoutHandler(w http.ResponseWriter, r *http.Request) {
	addNoCacheHeaders(w)
	if r.Method == "POST" {
		// Invalidate the token by setting the cookie's expiration date to the past
		http.SetCookie(w, &http.Cookie{
			Name:     "token",
			Value:    "",
			Expires:  time.Now().Add(-time.Hour),
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
		// Redirect to the login page
		http.Redirect(w, r, "/admin-login", http.StatusSeeOther)
	}
}
