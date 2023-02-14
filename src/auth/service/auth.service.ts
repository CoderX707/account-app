import {
  Injectable,
  InternalServerErrorException,
  Logger,
  NotAcceptableException,
  UnauthorizedException,
  UnprocessableEntityException,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import * as CryptoJS from 'crypto-js';

import { validationErrorMessage } from 'src/helper/errorConstants';
import { LoginUserDto } from '../dto/loginUser.dto';
import { RegisterUserDto } from '../dto/registerUser.dto';
import { UserSchema } from '../schema/userSchema';
import {
  ACCOUNT_VERIFY_SUCCESS,
  authRoute,
  EMAIL_PASSWORD_INVALID,
  FROM_USER_EMAIL,
  JWT_TOKEN_EXPIRED,
  JWT_TOKEN_NOTVALID,
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
        throw new NotAcceptableException(
          validationErrorMessage.isAlreadyExists('Email or Mobile number'),
        );
      } else {
        Logger.error(error);
        throw new InternalServerErrorException(SERVER_ERROR);
      }
    }
  }

  async login(loginUserDto: LoginUserDto) {
    const user: any = await this.validateUser(
      loginUserDto.email,
      loginUserDto.password,
    );
    delete user.password;
    const token = this.#jwtCreateToken(
      {
        id: user.id,
        name: user.firstName + ' ' + user.lastName,
        role: user.role,
        isBussinessAcount: user.isBussinessAcount,
        mobile: user.mobile,
        email: user.email,
        isMobileVerified: user.isMobileVerified,
        isEmailVerified: user.isEmailVerified,
        isAccountActive: user.isAccountActive,
      },
      '1d',
    );
    return { token };
  }

  async validateUser(email: string, password: string): Promise<any> {
    const user: any = await this.userModel.findOne({ email: email }).exec();
    if (!user) throw new NotAcceptableException('could not find the user');
    const passwordValid = await bcrypt.compare(password, user.password);
    if (!user) {
      throw new NotAcceptableException('could not find the user');
    }
    if (user && passwordValid) {
      return user;
    }
    throw new UnauthorizedException(EMAIL_PASSWORD_INVALID);
  }

  logout() {
    return;
  }

  async verifyAccount(token: string): Promise<string> {
    try {
      const { key = '' } = this.#jwtGetDetails(token);
      const user = this.#decryptKey(key);
      if (user && user.key && user.email && user.mobile) {
        await this.userModel
          .findOneAndUpdate(
            { email: user.email, mobile: user.mobile },
            { isEmailVerified: true, isAccountActive: true },
          )
          .exec();
        return ACCOUNT_VERIFY_SUCCESS;
      }
      throw new UnprocessableEntityException(JWT_TOKEN_EXPIRED);
    } catch (error) {
      Logger.error(error);
      if (error.status === 422) {
        throw new UnprocessableEntityException(JWT_TOKEN_EXPIRED);
      } else {
        throw new NotAcceptableException(JWT_TOKEN_NOTVALID);
      }
    }
  }

  checkAuthentication(token: string) {
    const { key = '' } = this.#jwtGetDetails(token);
    const user = this.#decryptKey(key);
    return user;
  }

  forgotPassword() {
    return;
  }

  #jwtGetDetails(token: string) {
    try {
      return this.jwtService.verify(token);
    } catch (error) {
      Logger.error(error);
      throw new NotAcceptableException(JWT_TOKEN_NOTVALID);
    }
  }

  #jwtCreateToken(data: any, expiresIn = '2h') {
    const key = this.#encryptKey(data);
    try {
      return this.jwtService.sign({ key }, { expiresIn: expiresIn });
    } catch (error) {
      Logger.error(error);
    }
  }

  #encryptKey(data: any) {
    return CryptoJS.AES.encrypt(
      JSON.stringify(data),
      process.env.CRYPTO_JS_KEY,
    ).toString();
  }

  #decryptKey(encryptText: string) {
    try {
      const bytes = CryptoJS.AES.decrypt(
        encryptText,
        process.env.CRYPTO_JS_KEY,
      );
      const decryptedData = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
      return decryptedData;
    } catch (error) {
      Logger.error(error);
    }
  }
}
