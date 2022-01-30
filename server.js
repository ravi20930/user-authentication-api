require("dotenv").config()

const express = require('express');
const mysql = require('mysql');
const bcrypt = require("bcrypt");
const bodyParser = require('body-parser')
const encoder = bodyParser.urlencoded({ extended: true })
const app = express();
app.use('/public', express.static('public'))
app.use(express.json())

const db = mysql.createPool({
    host: "localhost",
    user: "root",
    password: "password",
    database: "userdb",
})
db.getConnection((error) => {
    if (error) throw error
    else console.log("connected to db")
})

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/pages/index.html')
});

//user registration
app.post("/register", encoder, async (req, res) => {
    var user_name = req.body.user_name;
    var user_email = req.body.user_email;
    var hashedPassword = await bcrypt.hash(req.body.user_password, 10);

    db.getConnection(async (err, connection) => {
        if (err) throw (err)
        const sqlSearch = "SELECT * FROM userinfo WHERE user_name = ? OR user_email = ?"
        const searchQuery = mysql.format(sqlSearch, [user_name, user_email])
        const sqlInsert = "INSERT INTO userinfo VALUES (0,?,?,?)"
        const insert_query = mysql.format(sqlInsert, [user_name, user_email, hashedPassword])
        // ? will come from client in order

        await connection.query(searchQuery, async (err, result) => {
            if (err) throw (err)
            console.log("-------- search results --------")
            console.log(result.length)
            if (result.length != 0) {
                connection.release()
                console.log("-------- user already exists --------")
                res.sendStatus(409)
            }
            else {
                await connection.query(insert_query, (err, result) => {
                    connection.release()
                    if (err) throw (err)
                    console.log("-------- new user created --------")
                    console.log(result.insertId)
                    // res.sendStatus(201)
                    res.sendFile(__dirname + "/welcome.html")
                })
            }
        })
    })
}) //end of app.post() for registration



//user login starts ----------------------not able to log in always says user not exist????????????????
app.post("/login", (req, res) => {
    var user_name_or_email = req.body.user_name_or_email
    var user_password = req.body.user_password

    db.getConnection(async (err, connection) => {
        if (err) throw (err)
        const sqlSearch = "Select * from userinfo where user_name = ? or user_email = ?"
        const searchQuery = mysql.format(sqlSearch, [user_name_or_email, user_name_or_email])
        await connection.query(searchQuery, async (err, result) => {
            connection.release()

            if (err) throw (err)
            if (result.length == 0) {
                console.log("-------- user does not exist --------")
                res.sendStatus(404)
            }
            else {
                const hashedPassword = result[0].user_password
                //get the hashedPassword from result
                if (await bcrypt.compare(user_password, hashedPassword)) {
                    console.log("--------- login successful --------")
                    res.send(`${user_name} logged in`)
                }
                else {
                    console.log("--------- incorrect password --------")
                    res.send("incorrect password")
                }
            }
        })
    })
}) //end of app.post() for login



// generate access token after successful login
const generateAccessToken = require("./serverAuth")
app.post("/login", (req, res) => {
    var user_name_or_email = req.body.user_name_or_email
    const user_password = req.body.user_password

    db.getConnection(async (err, connection) => {
        if (err) throw (err)
        const sqlSearch = "Select * from userinfo where user_name = ? or user_email = ?"
        const searchQuery = mysql.format(sqlSearch, [user_name_or_email, user_name_or_email])
        await connection.query(searchQuery, async (err, result) => {
            connection.release()

            if (err) throw (err)
            if (result.length == 0) {
                console.log("-------- user does not exist --------")
                res.sendStatus(404)
            }
            else {
                const hashedPassword = result[0].password
                if (await bcrypt.compare(user_password, hashedPassword)) {
                    console.log("--------- login successful --------")
                    console.log("--------- generating accessToken --------")
                    const token = generateAccessToken({ user: user })
                    console.log(token)
                    res.json({ accessToken: token })
                } else {
                    res.send("incorrect password")
                }
            }
        })
    })
}) // access tokens after login ends


//------------- logout ---------------
app.delete("/logout", (req, res) => {
    //how?
    res.status(204).send("Logged out!")
})



app.get("/welcome", (req, res) => {
    res.sendFile(__dirname + "/pages/welcome.html")
})







app.listen(process.env.PORT, () => {
    console.log('started successfully on port: ' + process.env.PORT);
}); 
