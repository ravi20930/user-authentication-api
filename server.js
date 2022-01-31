require("dotenv").config()

const express = require('express');
const mysql = require('mysql');
const bcrypt = require("bcrypt");
const bodyParser = require('body-parser')
const jwt = require("jsonwebtoken")
const session = require('express-session');
const generateAccessToken = require("./generateAccessToken")

const encoder = bodyParser.urlencoded({ extended: true })
const app = express();
app.use(express.json())
app.use('/public', express.static('public'))

app.use(session({
    secret: 'seCReT',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 3600000 }
}));

const db = mysql.createPool({
    host: "localhost",
    user: "root",
    password: "password",
    database: "userdb",
})
db.getConnection((error) => {
    if (error) throw ("MySQL Connection Error: "+ error);
    else console.log("Connected to MySQL DB")
})

app.get('/', (req, res)=> {
    res.sendFile(__dirname + '/pages/index.html')
})

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
            if (result.length != 0) {
                connection.release()
                console.log("-------- user already exists --------")
                res.status(409).json({
                    msg: "User already Exists",
                });
            }
            else {
                await connection.query(insert_query, (err, result) => {
                    connection.release()
                    if (err) throw (err)
                    console.log("-------- new user created --------")
                    res.status(201).json({
                        msg: "New User Created",
                        user: {
                            user_id: result.insertId,
                            user_name: user_name,
                            user_email: user_email
                        }
                    });
                })
            }
        })
    })
}) //end of app.post() for registration


// generate access token after successful login
app.post("/login", encoder, (req, res) => {
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
                res.status(404).json({
                    msg: "User does not exists. Please /register",
                });
            }
            else {
                const hashedPassword = result[0].user_password
                if (await bcrypt.compare(user_password, hashedPassword)) {
                    const token = generateAccessToken({ user: result[0] })
                    req.session.token = token
                    res.status(200).json({
                        msg: 'Login Successful',
                        "token": token,
                        user: result[0]
                    });
                } else {
                    res.status(401).json({
                            msg: 'You entered the wrong password!'
                        });
                }
            }
        })
    })
}) // access tokens after login ends


//------------- logout ---------------
app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.status(200).json({msg: "Successfully Logged out!"});
    })
})



app.get("/welcome", encoder ,(req, res) => {
    var token = req.session.token
    if(token){

        const decode = jwt.verify(token, 'secret');

        res.status(200).json({
            msg: 'Authentication Successful',
            user: decode
        });
    }else{
        res.status(401).json({
            msg: 'Unauthenticated Access! Please pass the token.'
        });
    }
})

const port = process.env.port || 3000;
app.listen(port, () => {
    console.log('started successfully on port: ' + port);
}); 