import { Injectable, Logger, NotAcceptableException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';

import { validationErrorMessage } from 'src/helper/errorConstants';
import { LoginUserDto } from '../dto/loginUser.dto';
import { RegisterUserDto } from '../dto/registerUser.dto';
import { UserSchema } from '../schema/userSchema';
import {
  ACCOUNT_VERIFY_SUCCESS,
  authRoute,
  FROM_USER_EMAIL,
  JWT_TOKEN_EXPIRED,
  REGISTRATION_SUCCESS,
  SERVER_ERROR,
  SERVER_URL,
} from 'src/helper/constants';
import { MailerService } from '@nestjs-modules/mailer';
import { confirmAccountTemplate } from 'src/helper/mailHelper/mailTemplates/account_confirm';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel('user') private userModel: Model<typeof UserSchema>,
    private readonly jwtService: JwtService,
    private readonly mailerService: MailerService,
  ) {}

  async register(registerUserDto: RegisterUserDto): Promise<string> {
    try {
      const userSchema = new this.userModel(registerUserDto);
      const user: any = await userSchema.save();

      const token = this.#jwtCreateToken({
        key: user._id,
        name: user.firstName + ' ' + user.lastName,
        email: user.email,
        mobile: user.mobile,
      });

      await this.mailerService.sendMail({
        to: user.email,
        from: '📬 SSOVEE 📨' + FROM_USER_EMAIL,
        subject: 'Confirm your account',
        html: confirmAccountTemplate(
          SERVER_URL + authRoute.verify + '/?q=' + token,
        ),
      });

      return REGISTRATION_SUCCESS;
    } catch (error) {
      if (error.code === 11000) {
        return validationErrorMessage.isAlreadyExists('Email or Mobile number');
      } else {
        Logger.error(error);
        return SERVER_ERROR;
      }
    }
  }

  login(loginUserDto: LoginUserDto) {
    return loginUserDto;
  }

  async validateUser(email: string, password: string): Promise<any> {
    const user: any = await this.userModel.findOne({ email: email }).exec();
    if (!user) return null;
    const passwordValid = await bcrypt.compare(password, user.password);
    if (!user) {
      throw new NotAcceptableException('could not find the user');
    }
    if (user && passwordValid) {
      return user;
    }
    return null;
  }

  logout() {
    return;
  }

  async verify(token: string): Promise<string> {
    try {
      const user: any = this.#jwtGetDetails(token);
      if (user && user.key && user.email && user.mobile) {
        await this.userModel
          .findOneAndUpdate(
            { email: user.email, mobile: user.mobile },
            { isEmailVerified: true, isAccountActive: true },
          )
          .exec();
        return ACCOUNT_VERIFY_SUCCESS;
      }
      return JWT_TOKEN_EXPIRED;
    } catch (error) {
      Logger.error(error);
      return JWT_TOKEN_EXPIRED;
    }
  }

  forgotPassword() {
    return;
  }

  #bearerToToken(token: string) {
    return token.replace('Bearer ', '');
  }

  #jwtGetDetails(token: string) {
    return this.jwtService.verify(token);
  }

  #jwtCreateToken(data: any, expiresIn = '2h') {
    return this.jwtService.sign(data, { expiresIn: expiresIn });
  }
}
