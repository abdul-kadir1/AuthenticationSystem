import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';
import transporter from '../config/nodemailer.js';

// Signup/register Authentication 

export const register=async(req,res)=>{
  const {name,email,password}=req.body;

  if(!name || !email || !password){
    return res.json({success:false,message:'Missing Details'})
  }

  try{
    // User ko find kar rhe hain
    const existingUser = await userModel.findOne({email})

    // age user already exist karta hoga to yeh message show hoga
    if(existingUser){
      return res.json({success:false, message:"User already exists"});
    }
    // Hashing password
    const hashedPassword = await bcrypt.hash(password,10) 

    const user = new userModel({name , email, password:hashedPassword});
    await user.save();

    const token = jwt.sign({id:user._id},process.env.JWT_SECRET,{expiresIn:'7d'});

    res.cookie('token',token,{
      httpOnly:true,
      secure:process.env.NODE_ENV ==='production' ,
      sameSite:process.env.NODE_ENV==='production'?'none':'strict', 
      maxAge:7*24*60*60*1000  

    })
    // Sending Welcome email

      const mailOptions={
          from:process.env.SENDER_EMAIL,
          to:email,
          subject:'Welcome to the coder Community',
          text:`Welcome to our Application .Your account has been created with email id:${email}`,
    
      }

      await transporter.sendMail(mailOptions) 
  
    return res.json({success:true})

  }
  catch(error){
      res.json({success:false, message:error.message})
  }
}

// Login Authentication
export const login = async(req,res)=>{
  const {email,password} = req.body;

  if(!email || !password){
    return res.json({success:false,message:"Email and password are required"})
  }
  try{
    const user = await userModel.findOne({email});

    if(!user){
      return res.json({success:false,message:"Invalid email"})
    }

    const isMatch = await bcrypt.compare(password , user.password);

    if(!isMatch){
      return res.json({success:false,message:"Invalid password."})
    }

    const token = jwt.sign({id:user._id},process.env.JWT_SECRET,{expiresIn:'7d'});

    res.cookie('token',token,{
      httpOnly:true,
      secure:process.env.NODE_ENV ==='production' ,
      sameSite:process.env.NODE_ENV==='production'?'none':'strict', 
      maxAge:7*24*60*60*1000  

    })
    return res.json({success:true})
  }
  catch(error){
     return res.json({success:false,message:error.message})
  }

}

// Logout Authentication
export const logout=async(req,res)=>{
  try{
      res.clearCookie('token',{
        httpOnly:true,
        secure:process.env.NODE_ENV='production',
        sameSite:process.env.NODE_ENV='production'?'none':'strict',
      })
      return res.json({success:true,message:"Logged Out"})
  }
  catch(error){
    return res.json({success:false,message:error.message})
  }
} 


// send verification OTP to the User's Email

export const sendVerifyOtp=async(req,res)=>{
  try{
      const userId=req.user?.id; 
      const   user = await userModel.findById(userId);

      if(user.isAccountVerified){
          return res.json({success:false,message:"Account already verified"})
      }
        // Generating 6 digit OTP
  const otp = String (Math.floor(100000+Math.random()*900000))
  // storing it into db
  user.verifyOtp=otp;
  // applying expiry of otp
  user.verifyOtpExpireAt=Date.now()+24*60*60*1000

      // save the user in the DB
      await user.save();

      //sending otp
      const mailOptions={
        from:process.env.SENDER_EMAIL,
        to:user.email,
        subject:"Account Verification OTP",
        text:`Your OTP is ${otp}.Verify your account using this OTP.`
      }
      await transporter.sendMail(mailOptions);

      res.json({success:true,message:"Verification OTP sent to your Email"});
    
  }

  catch(error) {
  console.error("Error in sendVerifyOtp:", error);
  return res.status(500).json({
    success: false,
    message: "Server error while sending OTP"
  });
}

}


// When user Enter the OTP for verification on our application we have to verify
//    so here is the code..............

export const verifyEmail = async (req,res)=>{


   const userId = req.user?.id;//middleware se otp
   const {otp} = req.body;

  if(!userId || !otp){
    return res.json({success:false,message:"Missing details"});
  }
 try{

  const user = await userModel.findById(userId);
  if(!user){
    return res.json({success:false,message:'User not found'});
  }
  if(user.verifyOtp === '' || user.verifyOtp !== otp){
    return res.json({success:false,message:'Invalid OPT'});
  }
  
  if(user.verifyOtpExpireAt < Date.now()){
    return res.json({success:false,message:'OTP Expired'});
  }

  user.isAccountVerified=true;
  user.verifyOtp="";
  user.verifyOtpExpireAt=0;

  await user.save();
  return res.json({success:true,message:'Email verfified successfully'}) 

 } catch(error){
  return res.json({success:false,message:error.message});
 }

}



//  Check if User authenticated or not

export const isAuthenticated = async(req,res)=>{
  try{
    return res.json({success:true});
  }
  catch(error){
    res.json({success:false,message:error.message})
  }
}

// send Password Reset OTP on mail
export const sendResetOtp = async (req,res)=>{
  const {email} = req.body;
  if(!email){
    return res.json({success:false,message:"Email is required"})
  }

  try{
    const user = await userModel.findOne({email});
    if(!user){
      return res.json({message:false,message:"User not found"}); 
    }

     const otp = String (Math.floor(100000+Math.random()*900000))
  // storing it into db
  user.resetOtp=otp;
  // applying expiry of otp
  user.resetOtpExpireAt=Date.now()+15*60*1000

      // save the user in the DB
      await user.save();

      //sending otp
      const mailOptions={
        from:process.env.SENDER_EMAIL,
        to:user.email,
        subject:"Password Reset OTP",
        text:`Your OTP for resetting your password is ${otp} Use this OTP to proceed with reseting your password.`
      }
      await transporter.sendMail(mailOptions);
      return res.json({success:true,message:"OTP sent to your email.."})

  }
  catch(error){
    return res.json({message:false,message:error.message})
  }
}

// Reset User Password
export const resetPassword = async(req,res)=>{
  const {email,otp,newPassword} = req.body;

  if(!email || !otp || !newPassword){
    return res.json({success:false,message:`Email,OTP,and new password are required`});
  }
  try{
        const user =await userModel.findOne({email});
        if(!user){
          return res.json({success:false,message:"User not found"})
        }

        if(user.resetOtp == "" || user.resetOtp !==otp){
          return res.json({success:false,message:`Invalid OTP`})
        }

        if(user.resetOtpExpireAt < Date.now()){
          return res.json({success:false,message:"OTP Expired"});
        }

        const hashedPassword = await bcrypt.hash( newPassword,10);

        user.password = hashedPassword;
        user.resetOtp='';
        user.resetOtpExpireAt=0;

        await user.save();

        return res.json({success:true,message:'password has been reset successfully'})
  }
  catch(error){
    res.json({message:false,message:error.message})
  }
}