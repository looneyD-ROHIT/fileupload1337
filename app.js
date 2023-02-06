const express = require('express');
const mongoose = require('mongoose');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const morgan = require('morgan');
const session = require('express-session');
var passport = require('passport');
var crypto = require('crypto');
var LocalStrategy = require('passport-local').Strategy;
const MongoStore = require('connect-mongo');


// Configuring Multer
const multer = require("multer");
const multerStorage = multer.diskStorage({
    destination: (req, file, multerCb) => {
        const newPath = path.join('uploads', `${req.session.passport.user}`);
        fs.mkdirSync(newPath, { recursive: true });
        multerCb(null, newPath);
    },
    filename: (req, file, multerCb) => {
        const username = req.user.username ? req.user.username : 'local';
        const timeNow = `${new Date().getTime()}`
        const ext = path.extname(file.originalname);
        multerCb(null, `${username}-${timeNow}${ext}`);
    },
});
const upload = multer({
    storage: multerStorage,
});

const PORT = process.env.PORT || 1337;
require('dotenv').config();

// Create the Express application
var app = express();


// generic middlewares for basic express functionality
app.use(morgan('tiny'));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({extended: true}));

app.set('view engine', 'ejs');


// prevent browser caching
app.use((req, res, next)=>{
    res.set('Cache-control', 'no-store')
    next()
})

/**
 * -------------- DATABASE ----------------
 */

const MONGO_URL = process.env.DB_STRING;

mongoose.set("strictQuery", false);

mongoose.connect(MONGO_URL, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log(`Database Connection Established!`))
.catch(err => console.log(`Database Connection Failed! ` + err));


// importing the userschema
const User = require(path.join(__dirname, './model/userModel.js'));



/**
 * -------------- PASSPORT-LOCAL AUTH ---------------- 
 */
passport.use(new LocalStrategy(
    function(username, password, passportCB) {
        // console.log('passport: '+username+' '+password)
        User.findOne({ username: username })
            .then((user) => {

                // if user does not exist
                if (!user) { return passportCB(null, false) }
                
                const hashVerify = crypto.pbkdf2Sync(password, user.salt, 10000, 64, 'sha512').toString('hex');
                const isValid = user.password == hashVerify;
                
                // if user exists and password is valid
                if (isValid) {
                    return passportCB(null, user);
                } else {
                    return passportCB(null, false);
                }
            })
            .catch((err) => {   
                passportCB(err);
            });
}));


passport.serializeUser(function(user, passportCB) {
    passportCB(null, user.id);
});

passport.deserializeUser(function(id, passportCB) {
    User.findById(id, function (err, user) {
        if (err) { 
            return passportCB(err); 
        }
        passportCB(null, user);
    });
});


/**
 * -------------- SESSION SETUP ----------------
 */
app.use(session({
    secret: 'good boy',
    resave: false,
    saveUninitialized: true,
    store: MongoStore.create({
        mongoUrl: process.env.DB_STRING,
    }),
    cookie: {
        maxAge: 1000 * 60 * 60  * 24
    }
}));

app.use(passport.authenticate('session'));
app.use(passport.initialize());
app.use(passport.session());


function isLoggedIn( req, res, next ) {
    if(req.isAuthenticated())
        next();
    else{
        res.json({status:'fail', message:'Not Authenticated'})
    }
}

// middlewares to be run only if user is authenticated
// app.use('/static', express.static(path.join(__dirname, 'static')));
app.use('/views', express.static(path.join(__dirname, 'views')));
app.use('/uploads', isLoggedIn, express.static(path.join(__dirname, 'uploads')));

/**
 * -------------- ROUTES ----------------
 */

app.get('/', (req, res) => {
    if(req.isAuthenticated() && !req.user.admin){
        console.log(req.user)
        res.redirect('/dashboard')
    }else if(req.isAuthenticated() &&req.user.admin){
        res.redirect('/admin');
    }
    else{
        res.sendFile(path.join(__dirname, 'views/index.html'));
        // res.render('index');
    }
});

app.get('/login', (req, res, next) => {
    if(req.isAuthenticated()&& !req.user.admin){
        res.redirect('/dashboard');
    }else if(req.isAuthenticated() &&req.user.admin){
        res.redirect('/admin');
    }
    else{
        // res.sendFile(path.join(__dirname, 'static/login.html'));
        res.render('login');
    }
});

// Since we are using the passport.authenticate() method, we should be redirected no matter what 
app.post('/login', passport.authenticate('local', { failureRedirect: '/fail', successRedirect: '/dashboard' }), (err, req, res, next) => {
    if (err){
        console.log(`Error while loggin in ${err}`)
        next(err);
    }
});


app.get('/register', (req, res, next) => {
    if(req.isAuthenticated() && !req.user.admin){
        res.redirect('/dashboard');
    }else if(req.isAuthenticated() &&req.user.admin){
        res.redirect('/admin');
    }
    else{
        // res.sendFile(path.join(__dirname, 'static/register.html'));
        res.render('register');
    }
});

app.post('/register', (req, res, next) => {

    const salt = crypto.randomBytes(32).toString('hex');
    const hash = crypto.pbkdf2Sync(req.body.password, salt, 10000, 64, 'sha512').toString('hex');

    const newUser = new User({
        username: req.body.username,
        password: hash,
        salt: salt,
        admin: req.body.admin
    });

    const jsonData = {
        status: 'success',
        msg: 'registered'
    }
    newUser.save()
        .then((user) => {
            console.log(user);
            // console.log('khanki')
            console.log(jsonData)
            res.json(jsonData);
        }).catch((err) => {
            // console.log('gandu')
            console.log('Error while registering: '+err)
            jsonData.status = 'fail';
            jsonData.msg = 'not registered'
            console.log(jsonData)
            res.json(jsonData);
            // return res.redirect('/fail');
        })


});

app.get('/fail',  (req, res, next)=>{
    if(req.isAuthenticated() && !req.user.admin){
        res.redirect('/dashboard');
    }else if(req.isAuthenticated() &&req.user.admin){
        res.redirect('/admin');
    }
    else{
        // res.sendFile(path.join(__dirname, 'static/fail.html'));
        res.render('fail');
    }
})

app.get('/dashboard', (req, res, next)=>{
    if(req.isAuthenticated() && !req.user.admin){
        // res.json({id: req.user._id, username: req.user.username});
        // res.sendFile(path.join(__dirname, 'static/dashboard.html'));
        res.render('clientDashboard/dashboard', { user: `${req.user.username}`, id: `${req.user._id}` });
    }else if(req.isAuthenticated() &&req.user.admin){
        res.redirect('/admin');
    }
    else{
        // res.send('<h1>Not Authenticated!!!</h1>')
        res.redirect('/login');
    }
})

app.get('/logout', (req, res, next) => {
    if(req.isAuthenticated()){
        req.logout(function(err) {
            if (err) { return next(err); }
        });
    }
    res.redirect('/');
});


app.post('/upload', (req, res, next)=>{
    if(req.isAuthenticated()){
        next();
    }else{
        res.json({status: 'fail', message: 'you are not authenticated to upload files'})
    }
}, upload.single("files"), (req, res) => {
    res.json({ status: 'success', message: "Successfully uploaded files" });
});

app.post('/retrieve', (req, res, next)=>{
    if(req.isAuthenticated()){
        next();
    }else{
        res.json({status: 'fail', message: 'you are not authenticated to retrieve fileList'})
    }
}, (req, res) => {
    // console.log('Retrieving Files')
    const filesuserid = req.body.filesuserid;
    const filesusername = req.body.filesusername;
    try{
        const filesList = fs.readdirSync(`./uploads/${filesuserid}`);
        // console.log(filesList);
        
        if(filesList.length > 0){
            // console.log(filesList.length);
            return res.json({
                status: 'success',
                message: 'Successfully retrieved files',
                id: filesuserid,
                user: filesusername,
                filesList: filesList
            })
        }else{
            return res.json({
                status: 'fail',
                message: 'Error retrieving files'
            })
        }
    }catch(err){
        console.log('Error retrieving files (backend): ' + err);
        return res.json({
            status: 'fail',
            message: 'Error retrieving files'
        })
    }
})

app.post('/retrieveall', (req, res, next)=>{
    if(req.isAuthenticated() && req.user.admin){
        next();
    }else{
        res.json({status: 'fail', message: 'you are not authenticated to retrieve admin fileList'})
    }
}, (req, res) => {
    try{
        const folderList = fs.readdirSync(`./uploads`);
        // console.log(folderList)
        let jsonData = {};
        if(folderList.length > 0){
            for(let i=0; i<folderList.length; i++){
                let folder = folderList[i];
                if(folder[0]=='.') continue;
                const filesList = fs.readdirSync(`./uploads/${folder}`);
                jsonData[folder] = {
                    filesList: filesList
                }
            }
            jsonData = {
                ...jsonData,
                status: 'success',
                message: 'Successfully retrieved admin files',
            }
            // console.log(filesList.length);
            return res.json(jsonData);
        }else{
            jsonData = {
                ...jsonData,
                status: 'fail',
                message: 'Error retrieving files'
            }
            return res.json(jsonData);
        }
    }catch(err){
        console.log('Error retrieving admin files (backend): ' + err);
        jsonData = {
            ...jsonData,
            status: 'fail',
            message: 'Error retrieving files'
        }
        return res.json(jsonData);
    }
})

app.get('/admin', (req, res)=>{
    if(req.isAuthenticated() && req.user.admin){
        // res.json({status: 'success', message: 'admin panel access granted'})
        // res.sendFile(path.join(__dirname, 'static/adminpanel.html'));

        res.render('adminDashboard/adminPanel', { admin: `${req.user.username}`, id: `${req.user._id}` });
    }else if(req.isAuthenticated() && !req.user.admin){
        res.redirect('/dashboard')
    }
    else{
        res.redirect('/');
    }
})

app.post('/admin', (req, res, next) => {
    if(req.isAuthenticated() && req.user.admin){
        next()
    }else{
        res.json({status: 'fail', message: 'admin panel access not granted'})
    }
}, (req, res)=>{
    res.json({status: 'success', message: 'admin panel access granted'})
})

app.delete('/admin', (req, res, next) => {
    if(req.isAuthenticated() && req.user.admin){
        next()
    }else{
        res.json({status: 'fail', message: 'admin panel access not granted'})
    }
}, (req, res)=>{
    console.log(req.body.finalFilesList)
    const finalFilesList = req.body.finalFilesList;
    const folderList = Object.keys(finalFilesList);
    for(let i=0; i<folderList.length; i++){
        const folder = `${folderList[i]}`;
        for(let j=0; j<finalFilesList[folder].length; j++){
            const file = finalFilesList[folder][j];
            const filePath = `./uploads/${folder}/${file}`
            // console.log(filePath);
            try{
                fs.unlinkSync(filePath);
                console.log('Successfully deleted: ' + filePath)
            }catch(err){
                console.log('Error occurred while deleting: '+err);
                res.json({status:'fail', message:'failed to delete selected files'})
            }
        }
    }
    res.json({status:'success', message:'successfully deleted selected files'})
})

app.get('*', (req, res)=>{
    res.redirect('/');
})



app.listen(PORT, ()=>{
    console.log(`Running on http://localhost:${PORT}`);
});
