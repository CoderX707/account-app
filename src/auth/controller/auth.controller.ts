import { Body, Controller, Get, Post, Query, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import * as bcrypt from 'bcrypt';

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
      return CONFIRM_PASSWORD_NOT_MATCH;
    }
    const hasPassword = await bcrypt.hash(registerUserDto.password, 12);
    registerUserDto.password = hasPassword;
    return this.authService.register(registerUserDto);
  }

  @UseGuards(AuthGuard('local'))
  @Post(authRoute.login)
  login(@Body() loginUserDto: LoginUserDto) {
    return this.authService.login(loginUserDto);
  }

  @Post(authRoute.logout)
  logout() {
    return this.authService.logout();
  }

  @Get(authRoute.verify)
  verify(@Query('q') token: string) {
    return this.authService.verify(token);
  }

  @Post(authRoute.forgotPassword)
  forgotPassword() {
    return this.authService.forgotPassword();
  }
}
