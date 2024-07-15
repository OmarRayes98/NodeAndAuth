const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const register = async (req, res) => {

  const { first_name, last_name, email, password } = req.body;
  if (!first_name || !last_name || !email || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }

  const foundUser = await User.findOne({ email }).exec();
  if (foundUser) {
    return res.status(401).json({ message: 'User already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const user = await User.create({
    first_name,
    last_name,
    email,
    password: hashedPassword,
  });

  //jwt.sign : to create accesToken , inside accessToken has info of user's id and when decode token I can get id 
  const accessToken = jwt.sign(
    //with encode of token I store id of user 
    {
      UserInfo: {
        id: user._id,
      },
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: "15m" }
  );
  //after finish refresh token . you (have to )login again .
  const refreshToken = jwt.sign(
    {
      UserInfo: {
        id: user._id,
      },
    },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: '7d' }
  );

  // cookie(name of cookie , value of storing, { properties})
  res.cookie('jwt', refreshToken, {
    httpOnly: true, //accessible only by web server
    secure: true, //https
    sameSite: 'None', //cross-site cookie , // "strict" mean : sub-domain will not recive cookies
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days same expiresIn refreshToken
  });
  res.json({
    accessToken,
    email: user.email,
    first_name: user.first_name,
    last_name: user.last_name,
  });
};

//____________________________
//____________________________
const login = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'All fields are required' });
  }
  const foundUser = await User.findOne({ email }).exec();

  if (!foundUser) {
    return res.status(401).json({ message: 'User does not exist' });
  }

  //password : from front-end , foundUser.password : from dataBase 
  const match = await bcrypt.compare(password, foundUser.password);

  if (!match) return res.status(401).json({ message: 'Wrong Password' });


  const accessToken = jwt.sign(
    {
      UserInfo: {
        id: foundUser._id,
      },
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: "15m" }
  );
  const refreshToken = jwt.sign(
    {
      UserInfo: {
        id: foundUser._id,
      },
    },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: '7d' }
  );
  res.cookie('jwt', refreshToken, {
    httpOnly: true, //accessible only by web server
    secure: true, //https
    sameSite: 'None', //cross-site cookie
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
  res.json({
    accessToken,
    email: foundUser.email,
  });
};

//____________________________
//____________________________
/*

*/
const refresh = (req, res) => {

  // to get all cookies of browser then get cookies ("jwt name of cookie")  refreshToken by back-end , not front-end 
  const cookies = req.cookies;
  
  //if not exsited
  if (!cookies?.jwt) res.status(401).json({ message: 'Unauthorized' });

  //this refreshToken was stored in browser . I need it to check if still available ( expires still works)
  const refreshToken = cookies.jwt;


  jwt.verify(
    refreshToken,
    process.env.REFRESH_TOKEN_SECRET,
    async (err, decoded) => {
      // if err mean expired of refreshToken is finished
      if (err) return res.status(403).json({ message: 'Forbidden' });

      // if refreshToken still works : 
      const foundUser = await User.findById(decoded.UserInfo.id).exec();

      //if user not exsited stop will error
      if (!foundUser) return res.status(401).json({ message: 'Unauthorized' });

      //create new AccessToken and store inside (encode) token (user's id)
      const accessToken = jwt.sign(
        {
          UserInfo: {
            id: foundUser._id,
          },
        },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "15m" }
      );
      res.json({ accessToken });
    }
  );
};

//____________________________
//____________________________


const logout = (req, res) => {
  const cookies = req.cookies;
  if (!cookies?.jwt) return res.sendStatus(204); //No content
  res.clearCookie('jwt', {
    httpOnly: true,
    sameSite: 'None',
    secure: true,
  });
  res.json({ message: 'Cookie cleared' });
};
module.exports = {
  register,
  login,
  refresh,
  logout,
};
