const jwt = require("jsonwebtoken");

const verifyJWT = (req, res, next) => {
  // get AccessToken from header 
  const authHeader = req.headers.authorization || req.headers.Authorization; // "Bearer token"

  //Unauthorized : you don't login
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  
  const token = authHeader.split(" ")[1]; // ["Bearer","token"]
  
  //is still accessToken works (expires still works)
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    
    //accessToken has expired 
    if (err) return res.status(403).json({ message: "Forbidden" });
    
    //it works continue to invoke next api 
    req.user = decoded.UserInfo.id; //after decode token I can get id of user ( maybe will be useful to use id of user )
    next();
  });
};
module.exports = verifyJWT;
