// Description: This file contains the functions for the user routes
// TODO: add function check, to check if the server is alive
// TODO: add function to get all users
// TODO: add function to get a user by id
// TODO: add function to create a user
// TODO: add function to update a user
// TODO: add function to delete a user
// TODO: add function to check if a token is valid

import { Request, Response, NextFunction } from "express";
import CustomError from "../../classes/CustomError";
import { User } from "../../interfaces/User";
import { validationResult } from "express-validator";
import userModel from "../models/userModel";
import bcrypt from "bcrypt";
import DBMessageResponse from "../../interfaces/DBMessageResponse";
import jwt from "jsonwebtoken";
const userPost = async (
  req: Request<{}, {}, User>,
  res: Response,
  next: NextFunction
) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      const messages = errors
        .array()
        .map((error) => `${error.msg}: ${error.param}`)
        .join(", ");
      next(new CustomError(messages, 400));
      return;
    }

    const user = req.body;
    console.log("postUser", user);
    user.password = await bcrypt.hash(user.password, 12);

    const newUser = await userModel.create(user);
    const response: DBMessageResponse = {
      message: "User created",
      user: {
        user_name: newUser.user_name,
        email: newUser.email,
        id: newUser._id,
      },
    };

    res.json(response);
  } catch (error) {
    console.log(error);
    next(new CustomError("User creation failed", 500));
  }
};

const userListGet = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const users = await userModel.find().select("-password -role -__v");
    const response: DBMessageResponse = {
      message: "Users found",
      user: users,
    };

    res.json(response);
  } catch (error) {
    next(new CustomError("Users not found", 500));
  }
};

const userGet = async (
  req: Request<{ id: string }, {}, {}>,
  res: Response,
  next: NextFunction
) => {
  try {
    const user = await userModel
      .findById(req.params.id)
      .select("-password -role -__v");

    if (!user) {
      next(new CustomError("User not found", 404));
      return;
    }

    const response: DBMessageResponse = {
      message: "User found",
      user: user,
    };

    res.json(response);
  } catch (error) {
    next(new CustomError("User not found", 500));
  }
};

const userPut = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    console.log("auth server: token", token, req.body);
    if (!token) {
      return next(new CustomError("No token provided.", 401));
    }
    let decodedToken: any;

    try {
      decodedToken = jwt.verify(token, process.env.JWT_SECRET!);
    } catch (err) {
      return next(new CustomError("Token is invalid.", 403));
    }

    if (!decodedToken?.id) {
      return next(new CustomError("Invalid token.", 403));
    }

    // Assuming you have user data in req.body
    const updatedFields = req.body;
    if (updatedFields.password) {
      updatedFields.password = await bcrypt.hash(updatedFields.password, 12);
    }

    const user = await userModel.findByIdAndUpdate(
      decodedToken.id,
      updatedFields,
      {
        new: true,
        runValidators: true,
      }
    );

    if (!user) {
      return next(new CustomError("User not found.", 404));
    }

    // Respond with the updated user data without sensitive fields
    res.json({
      message: "User updated successfully",
      user: {
        user_name: user.user_name,
        email: user.email,
        id: user._id,
      },
    });
  } catch (error) {
    console.log(error);
    next(new CustomError("Failed to update user.", 500));
  }
};
const userDelete = async (
  req: Request<{ id: string }, {}, {userId: string;}>,
  res: Response,
  next: NextFunction
) => {
  console.log('REQ BODY', req.body);
  const token = req.headers.authorization?.split(" ")[1];
  console.log("auth server: token", token, req.body);
  if (!token) {
    return next(new CustomError("No token provided.", 401));
  }
  let decodedToken: any;

  try {
    decodedToken = jwt.verify(token, process.env.JWT_SECRET!);
  } catch (err) {
    return next(new CustomError("Token is invalid.", 403));
  }

  if (!decodedToken?.id) {
    return next(new CustomError("Invalid token.", 403));
  }

  try {
    let userIdToDelete;

    if (decodedToken.role === "admin") {
      userIdToDelete = req.body.userId;
    } else {

      console.log('Token ID:', decodedToken.id);
      console.log('Request ID:', req.body);
      userIdToDelete = decodedToken.id;
    }

    const deletedUser = await userModel.findByIdAndRemove(userIdToDelete);
    if (!deletedUser) {
      next(new CustomError("User not found", 404));
      return;
    }

    const response: DBMessageResponse = {
      message: "User deleted",
      user: deletedUser,
    };

    res.json(response);
  } catch (error) {
    next(new CustomError("User delete failed", 500));
  }
};

export { userPost, userListGet, userGet, userPut, userDelete };
