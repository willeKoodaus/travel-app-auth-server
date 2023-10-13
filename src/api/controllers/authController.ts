import {Request, Response, NextFunction} from 'express';
import CustomError from '../../classes/CustomError';
import {User} from '../../interfaces/User';
import {validationResult} from 'express-validator';
import userModel from '../models/userModel';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import LoginMessageResponse from '../../interfaces/LoginMessageResponse';

const loginPost = async (
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
        .join(', ');
      next(new CustomError(messages, 400));
      return;
    }

    const {email, password} = req.body;
    console.log("Request body:", req.body);
    const user = await userModel.findOne({email});

    if (!user) {
      next(new CustomError('Incorrect username/password', 403));
      return;
    }

    if (!(await bcrypt.compare(password, user.password))) {
      next(new CustomError('Incorrect username/password', 403));
      return;
    }

    const token = jwt.sign(
      {id: user._id, role: user.role},
      process.env.JWT_SECRET as string
    );

    const message: LoginMessageResponse = {
      message: 'Login successful',
      user: {
        user_name: user.user_name,
        email: user.email,
        id: user._id,
      },
      token: token,
    };
    console.log(message);
    res.json(message);
  } catch (error) {
    next(new CustomError('Login failed', 500));
  }
};

export {loginPost};
