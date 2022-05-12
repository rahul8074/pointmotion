var express = require('express');
var app = express();
// for parsing the body in POST request
var bodyParser = require('body-parser');
const database = require('./db.json')
const port = 3000

const jwt = require("jsonwebtoken");
const bcrypt = require('bcrypt');
const saltRounds = 10;
 
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

var fs = require('fs');
const { time } = require('console');
const { stringify } = require('querystring');
const { use } = require('bcrypt/promises');

//get detail
app.get('/user/me',function(req, res){
    const authHeader = req.get('Authorization');
    if (!authHeader) {
        res.json({result:false,error:"WT Verification Failed"});
    }
    var header =  authHeader ? authHeader.split(" ") : "";
    var token = header[header.length-1]
    
    var foundUserData = null;
    var userFound = false;
    database.forEach(data => {
        if (data.jwt == token) {
            foundUserData = data
            userFound = true;
        }
    })
    if (userFound == true) {
        res.json({result:true,data:{fname:foundUserData.fname,lname:foundUserData.lname,password:foundUserData.password}})
    }
    else {
        res.json({result:false,error:"Please provide a JWT token"});
    }


})

// GET /api/users
app.post('/signin/', function(req, res){
    let user = req.body;
    var userFound = false;
    var foundUserData = null;
    database.forEach(data => {
        if (user.username === data.username) {
            foundUserData = data
            userFound = true;
        }
    })
    if (userFound == true) {
        bcrypt.compare(user.password, foundUserData.password, async function(err, response){
            if(response === true){
                res.json({auth: true,username: foundUserData.username, password:foundUserData.passwordl, message:"Signin success", token:foundUserData.jwt});
            }
            else if(response===false){
                res.json({ auth:false, message:"Incorrect credentials"});
            }
        });
    }
    else {
        res.json("User not found");
    }
     
});

app.post('/signup/', function (req, res) {
    let user = req.body;

    var usernameLength = false
    if (user.username.length >= 4) {
        usernameLength = true
    }
    var userNameNotNumber = false
    if (isNaN(user.username)) {
        userNameNotNumber = true;
    }
    var fnameLnameRegex = /^[A-Z,a-z]+$/
    var usernameRegex = /^[a-z]+$/
    var passwordRegex = /^(?=.{8,})(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).*$/
    //validations 
    if (!usernameRegex.test(user.username)) {
        res.json({
            "result": false,
            "message": "username contains lowercase alphabets only"
          }); 
    }
    else if (!usernameLength) {
        res.json({
            "result": false,
            "message": "username length should be greater than or equal to 5"
          }); 
    }
    else if (!fnameLnameRegex.test(user.fname) || !fnameLnameRegex.test(user.lname) || user.fname.length==0 || user.lname.length==0) {
        res.json({
            "result": false,
            "message": "fname and lname should lowercase and uppercase"
          }); 
    }
    else if (!user.username || !user.password) {
        res.json({
            "result": false,
            "message": "username and password required"
          }); 
    } else if (!passwordRegex.test(user.password) || user.password.length<5) {
        res.json({
            "result": false,
            "message": "password must contain atleast lowercase ,uppercase ,number and special character and length min 5"
          }); 
    }
    

    var userAlreadyExists = false;
    database.forEach(data => {
        if (user.username === data.username) {
            userAlreadyExists = true;
            return res.send(`username ${user.username} already exists.`);    
        }
    })
  
    if (userAlreadyExists == false && userNameNotNumber && usernameLength) {
        const token = jwt.sign(
            { username: user.username, password:user.password},
            "secretkey",
            { expiresIn: "30d" }
          );
        bcrypt.genSalt(saltRounds, (err, salt) => {
            bcrypt.hash(user.password, salt, (err, hash) => {
                // Now we can store the password hash in db.
                user.password = hash;
                user.jwt = token;
                database.push(user);
                fs.writeFile ("db.json", JSON.stringify(database), function(err) {
                    if (err) throw err;
                    }
                );
            });
        });
        res.send({
            "result": true,
            "message": "SignUp success. Please proceed to Signin"
          });  
    }
   
});

app.listen(port, () => console.log(`Server listening on port ${port}`));