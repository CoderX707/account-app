import mongoose from 'mongoose';
import { validationErrorMessage } from 'src/helper/errorConstants';

export const UserSchema = new mongoose.Schema(
  {
    firstName: {
      type: String,
      trim: true,
      required: [
        true,
        validationErrorMessage.isRequiredErrorMessage('first name'),
      ],
    },
    lastName: {
      type: String,
      trim: true,
      required: [
        true,
        validationErrorMessage.isRequiredErrorMessage('last name'),
      ],
    },
    role: {
      type: String,
      enum: ['NORMAL', 'SSOVEEADMIN'],
      default: 'NORMAL',
    },
    isBussinessAcount: {
      type: Boolean,
      default: false,
    },
    mobile: {
      type: Number,
      trim: true,
      unique: true,
      required: [
        true,
        validationErrorMessage.isRequiredErrorMessage('mobile number'),
      ],
    },
    email: {
      type: String,
      unique: true,
      lowercase: true,
      trim: true,
      match: [
        /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/,
        'Please add a valid email',
      ],
    },
    password: {
      type: String,
      required: true,
    },
    isMobileVerified: {
      type: Boolean,
      default: false,
    },
    isEmailVerified: {
      type: Boolean,
      default: false,
    },
    isAccountActive: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true },
);
