import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseIntPipe,
  Post,
  Res,
  UseGuards,
} from "@nestjs/common";

import { Response } from "express";
import { CreateAdminDto } from "../../admin/dto/create-admin.dto";
import { AdminAuthService } from "./auth.service";
import { SignInDto } from "../dto/sign-in.dto";

@Controller("auth-admin")
export class AdminAuthController {
  constructor(private readonly adminService: AdminAuthService) {}

  @Post("sign-up")
  signUp(@Body() createAdminDto: CreateAdminDto) {
    return this.adminService.signUp(createAdminDto);
  }

  @HttpCode(HttpStatus.OK)
  @Post("sign-in")
  async singIn(
    @Body() singInDto: SignInDto,
    @Res({ passthrough: true }) res: Response
  ) {
    return this.adminService.signIn(singInDto, res);
  }

  // @Get('sign-out')
  // singout(
  //   @Res({ passthrough: true }) res: Response,
  // ) {
  //   return this.adminService.signOut(refreshToken, res);
  // }

  // @ApiOperation({ summary: 'Tokenni yangilash (refresh token)' })
  // @ApiResponse({
  //   status: 200,
  //   description: 'Yangilangan access va refresh tokenlar',
  // })
  // @ApiParam({ name: 'id', type: Number, description: 'Admin IDsi' })
  // @ApiCookieAuth()
  // @HttpCode(200)
  // @Post(':id/refresh')
  // refresh(
  //   @Param('id', ParseIntPipe) id: number,
  //   @CookieGetter('refresh_token') refreshToken: string,
  //   @Res({ passthrough: true }) res: Response,
  // ) {
  //   return this.adminService.refreshToken(id, refreshToken, res);
  // }
}
