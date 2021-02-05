const User = require('../models/User')
const jwt = require('jsonwebtoken')

// handle erros
const handleErrors = (err) => {
  console.log(err.message, err.code)
  let errors = { email: '', password: '' }
  // incorrec emial
  if (err.message === 'incorrect email') {
    errors.email = 'That email is not registered'
  }
  if (err.message === 'incorrect password') {
    errors.password = 'Hmm.. did you forget?'
  }

  // duplicate email
  if (err.code === 11000) {
    errors.email = 'That email is already in use.'
    return errors
  }
  // validation errors
  if (err.message.includes('user validation failed')) {
    Object.values(err.errors).forEach(({ properties }) => {
      errors[properties.path] = properties.message
    })
  }
  return errors
}

// create a token
// days * hours * minutes * seconds
const maxAge = 3 * 24 * 60 * 60
const createToken = (id) => {
  return jwt.sign({ id }, 'secret', {
    expiresIn: maxAge,
  })
}

// get html pages
const signup_get = (req, res) => {
  res.render('signup')
}
const login_get = (req, res) => {
  res.render('login')
}
// sending and recieving data
const signup_post = async (req, res) => {
  const { email, password } = req.body
  try {
    const user = await User.create({ email, password })
    const token = createToken(user._id)
    res.cookie('jwt', token, { httpOnly: true, maxAge: maxAge * 1000 })
    res.status(201).json({ user: user._id })
  } catch (err) {
    const errors = handleErrors(err)
    res.status(400).json({ errors })
  }
}
const login_post = async (req, res) => {
  const { email, password } = req.body
  try {
    const user = await User.login(email, password)
    const token = createToken(user._id)
    res.cookie('jwt', token, { httpOnly: true, maxAge: maxAge * 1000 })
    res.status(200).json({ user: user._id })
  } catch (err) {
    const errors = handleErrors(err)
    res.status(400).json({ errors })
  }
}
const logout_get = (req, res) => {
  res.cookie('jwt', '', { maxAge: 1 })
  res.redirect('/')
}

module.exports = {
  signup_get,
  signup_post,
  login_get,
  login_post,
  logout_get,
}
