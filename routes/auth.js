const router = require('express').Router();
const User = require('../model/User');
const { registerValidation, loginValidation } = require('./validation');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
//validacao




router.post('/register', async (req, res) => {

//validandno o dado antes de registrar o ususario
   const { error } = registerValidation(req.body);
   if(error) return res.status(400).send(error.details[0].message);
  


    //checando se o usuario ja esta na base
    const emailExist = await User.findOne({email: req.body.email});
    if(emailExist) return res.status(400).send('Email já existe!')
    
    // hash password
    const salt = await bcrypt.genSalt(10);
    const hashPassword  = await bcrypt.hash(req.body.password, salt);
   
    //criando novo usuario
    const user = new User({
        name: req.body.name,
        email: req.body.email,
        password: hashPassword
    });
    try {
        const savedUser = await user.save();
        res.send({user: user._id})
    } catch (err) {
        res.status(400).send(err)
    }
});



//login

router.post('/login', async (req,res) => {
   const { error } = loginValidation(req.body);
   if(error) return res.status(400).send(error.details[0].message);

   const user = await User.findOne({email: req.body.email});
   if(!user) return res.status(400).send('Email não existe!');
    // password is correct
   const validPass = await bcrypt.compare(req.body.password, user.password);
   if(!validPass) return res.status(400).send('Senha incorreta');


    // criando e declarando o token

   const token = jwt.sign({_id: user._id}, process.env.TOKEN_SECREAT);
   res.header('auth-token', token).send(token);

   //stres.send('Logado, seu filha da puta!')

})


module.exports = router;