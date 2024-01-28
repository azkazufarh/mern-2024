import User from "../models/user.model.js";
import bcryptjs from "bcryptjs";
import { errorHandler } from "../utils/error.js";
import jwt from "jsonwebtoken";

export const signup = async (req, res, next) => {
  const { username, email, password } = req.body;

  if (
    !username ||
    !email ||
    !password ||
    username === "" ||
    email === "" ||
    password === ""
  ) {
    next(errorHandler(400, "All fields are require!"));
  }

  const hashedPassword = bcryptjs.hashSync(password, 10);

  const newUser = new User({
    username,
    email,
    password: hashedPassword,
  });

  try {
    await newUser.save();
    res.status(201).json({ message: "Sign up successfull!" });
  } catch (error) {
    next(error);
  }
};
export const signin = async (req, res, next) => {
  const { username, password } = req.body;

  if (!username || !password || username === "" || password === "") {
    next(errorHandler(400, "All fields are require!"));
  }

  try {
    const valideUser = await User.findOne({ username });
    if (!valideUser) {
      next(errorHandler(404, "User not found"));
    }
    const validePassword = bcryptjs.compareSync(password, valideUser.password);
    if (!validePassword) {
      return next(errorHandler(404, "Invalid user password"));
    }

    const token = jwt.sign({ id: valideUser._id }, process.env.JWT_SECRET);
    const { password: pass, ...rest } = valideUser._doc;

    res
      .status(200)
      .cookie("access_token", token, { httpOnly: true })
      .json(rest);
  } catch (error) {
    next(error);
  }
};
