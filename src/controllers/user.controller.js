import { asyncHandler } from "../utils/asyncHandler.js";
import {ApiError} from "../utils/ApiError.js"
import {User} from "../models/user.model.js"
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken"

const generateAccessAndRefreshTokens = async(userId)=>{
    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken;
        await user.save({validateBeforeSave: false})

        return {accessToken, refreshToken}

    } catch (error) {
        throw new ApiError(500,"something went wrong while generating access and refresh tiken")
    }
}

const registerUser = asyncHandler ( async(req, res)=>{
  
    // get user details from frontend
    // validation - not empty
    // check if user already exists: username, email
    // check for images, check for coverImage
    // upload them to cloudinary,check for coverImage
    // create user object - create entry in db
    // password and refresh token field from response
    // check for user response
    // return response 


    const {fullName, email, username, password} = req.body
    console.log("email :",email)

   if (
    [fullName, email,username,password].some((field)=>
    field?.trim() === "")
   ) {
        throw new ApiError(400, "All fields are required")
   }


   const existedUser =  await User.findOne({
    $or:[{username},{email}]
   })
   if (existedUser) {
    throw new ApiError(409, "User with email or username already exists")
   }

   console.log(req.files)
   const avatarLocalPath = req.files?.coverImage[0]?.path;
   console.log(avatarLocalPath)
//    const coverImageLocalPath =  req.files?.coverImage[0]?.path;

   let coverImageLocalPath;
   if (req.files && Array.isArray(req.files.
    coverImage) && req.files.coverImage.length > 0 )
    {
        coverImageLocalPath=req.files.coverImage[0].path
   }

   if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is required")
   }

   const coverImage = await uploadOnCloudinary(avatarLocalPath)
   const coverImage =  await uploadOnCloudinary(coverImageLocalPath)
   console.log(coverImage)
   if (!coverImage) {
        throw new ApiError(400, "Avatar file is required")
   }

   const user =  await User.create({
    fullName,
    coverImage:coverImage.url,
    coverImage: coverImage?.url || "",
    email,
    password,
    username: username.toLowerCase()
   })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if (!createdUser) {
        throw new ApiError(500,"Something Went wrong while registering the user")
    }

    return res.status(201).json(
        new ApiResponse(200,createdUser, "User registered successfully")
    )

})

const loginUser = asyncHandler(async(req,res)=>{
    // req body --> data
    // login through username or email
    // find the user
    // password check
    // access and refresh token
    // send cookie

    const {email, username, password} = req.body;

    if (!(email || username)) {
        throw new ApiError(400, "username or password is required")
    }

    const user = await User.findOne({
        $or:[{username},{email}]
    })

    if (!user) {
        throw new ApiError(404, "User does not exist")
    }

    const isPasswordValid = await user.isPasswordCorrect(password)

    if (!isPasswordValid) {
        throw new ApiError(401,"Invalid user credentials")
    }

    const {accessToken, refreshToken}=await generateAccessAndRefreshTokens(user._id)

    const loggedInUser = await User.findOne(user._id).
    select("-password -refreshToken")

    const options={
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken",accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(
            200,
            {
                user:loggedInUser, accessToken, refreshToken
            },
            "User logged in successfully"
        )
    )
})

const logoutUser = asyncHandler(async(req,res)=>{
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        {
            new: true
        }
    )

    const options={
        httpOnly: true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken",options)
    .clearCookie("refreshToken",options)
    .json(
        new ApiResponse(200, {}, "User logged out")
    )
})

const refreshAccessToken = asyncHandler(async(req,res)=>{
    const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

    if (!incomingRefreshToken) {
        throw new ApiError(401,"Unauthorized request")
    }

    try {
        const decodedToken = jwt.verify(incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )
    
        const user = await User.findById(decodedToken?._id)
        if (!user) {
            throw new ApiError(401, "Invalid Refresh Token")
        }
    
        if (incomingRefreshToken !== user?.refreshToken) {
            throw new ApiError(401,"Refresh Token is expired or used")
        }
    
        const options={
            httpOnly: true,
            secure: true
        }
    
        const {accessToken,newRefreshToken} =  await generateAccessAndRefreshTokens(user._id)
    
        res
        .status(200)
        .cookie("accessToken",accessToken,options)
        .cookie("refreshToken",newRefreshToken,options)
        .json(
            new ApiResponse(
                200,
                {accessToken, refreshToken : newRefreshToken},
                "Access Token Refreshed"
            )
        )
    } catch (error) {
        throw new ApiError(401,error?.message ||
            "Invalid Refresh token"
        )
    }
})


const changeCurrentPassowrd = asyncHandler(async(req,res)=>{

    const {oldPassword, newPassword} = req.body;

    const user = await User.findById(user?._id)
    const isPasswordCorrects = await user.isPasswordCorrect(oldPassword)

    if (!isPasswordCorrects) {
        throw ApiError(400,"Invalid Old password")
    }
    user.password = newPassword;
    await user.save({validateBeforeSave: false})

    return res
    .status(200)
    .json(
        new ApiResponse(200,{},"Password changed successfully")
    )
})


const getCurrentUser = asyncHandler(async(req,res)=>{
    return res
    .status(200)
    .json(200, req.user, "current user fetched successfully")
})

const updateAccountDetails = asyncHandler(async(req,res)=>{

    const {fullName, email} = req.body;

    if (!(fullName || email)) {
        throw ApiError(400, "All fields are required")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                fullName,
                email
            }
        },
        {
            new: true
        }
    ).select("-password")

    return res
    .status(200)
    .json( new ApiResponse( 200, user,
    "Account Details updated successfully"))
})


const updateUserAvatar = asyncHandler(async(req,res)=>{

    const avatarLocalPath =  req.file?.path

    if (!avatarLocalPath) {
        throw ApiError(400, "Avatar file is missing")
    }

    const coverImage = await uploadOnCloudinary(avatarLocalPath)

    if (!coverImage.url) {
        throw ApiError(400, "Error while uploading an coverImage")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                coverImage: coverImage.url
            }
        },
        {
            new:true
        }
    ).select("-password")

    return res
    .status(200)
    .json(
        new ApiResponse(200, user, "avatar updated successfully")
    )
})


const updateUserCoverImage = asyncHandler(async(req,res)=>{

    const coverImageLocalPath =  req.file?.path

    if (!coverImageLocalPath) {
        throw ApiError(400, "Avatar file is missing")
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if (!coverImage.url) {
        throw ApiError(400, "Error while uploading an coverImage")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                coverImage: coverImage.url
            }
        },
        {
            new:true
        }
    ).select("-password")

    return res
    .status(200)
    .json(
        new ApiResponse(200, user, "Cover Iamge updated successfully")
    )
})

export {registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassowrd,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage
}