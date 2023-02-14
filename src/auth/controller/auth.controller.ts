import {
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Query,
  Req,
  UnauthorizedException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { Request } from 'express';

import { authRoute, CONFIRM_PASSWORD_NOT_MATCH } from 'src/helper/constants';
import { LoginUserDto } from '../dto/loginUser.dto';
import { RegisterUserDto } from '../dto/registerUser.dto';
import { AuthService } from '../service/auth.service';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post(authRoute.register)
  async register(@Body() registerUserDto: RegisterUserDto) {
    if (registerUserDto.confirmPassword !== registerUserDto.password) {
      throw new UnauthorizedException(CONFIRM_PASSWORD_NOT_MATCH);
    }
    const hasPassword = await bcrypt.hash(registerUserDto.password, 12);
    registerUserDto.password = hasPassword;
    return this.authService.register(registerUserDto);
  }

  @HttpCode(200)
  @Post(authRoute.login)
  login(@Body() loginUserDto: LoginUserDto) {
    return this.authService.login(loginUserDto);
  }

  @Post(authRoute.logout)
  logout() {
    return this.authService.logout();
  }

  @Get(authRoute.verify)
  verifyAccount(@Query('q') token: string) {
    return this.authService.verifyAccount(token);
  }

  @Post(authRoute.checkAuthentication)
  checkAuthentication(@Req() request: Request) {
    const { authorization, x_secret_key } = request.headers;
    if (authorization && x_secret_key === process.env.X_SECRET_KEY) {
      return this.authService.checkAuthentication(
        this.#bearerToToken(authorization),
      );
    }
    throw new UnauthorizedException();
  }

  @Post(authRoute.forgotPassword)
  forgotPassword() {
    return this.authService.forgotPassword();
  }

  #bearerToToken(token: string) {
    return token.replace('Bearer ', '');
  }
}
