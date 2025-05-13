import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
// import { SignInDto } from '../dto/sing-in.dto';

import { Response } from 'express';
import * as bcrypt from 'bcrypt';
// import { CreateStaffDto } from '../../staffs/dto/create-staff.dto';
import { AdminService } from '../../admin/admin.service';
import { Admin } from '../../admin/models/admin.model';
import { CreateAdminDto } from '../../admin/dto/create-admin.dto';
import { SignInDto } from '../dto/sign-in.dto';

@Injectable()
export class AdminAuthService {
  constructor(
    private readonly adminService: AdminService,
    readonly jwtService: JwtService,
  ) {}

  private async generateTokenAdmin(admin: Admin) {
    const payload = {
      id: admin.id,
      email: admin.email,
      password: admin.hashed_password,
      is_creater: admin.is_creater
    };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: process.env.ACCESS_TOKEN_KEY,
        expiresIn: process.env.ACCESS_TOKEN_TIME,
      }),
      this.jwtService.signAsync(payload, {
        secret: process.env.REFRESH_TOKEN_KEY,
        expiresIn: process.env.REFRESH_TOKEN_TIME,
      }),
    ]);
    return {
      accessToken,
      refreshToken,
    };
  }
  async signUp(createAdminDto: CreateAdminDto) {
    const admin = await this.adminService.findAdminByEmail(
      createAdminDto.email,
    );

    if (admin) {
      throw new ConflictException('Bunday emailli foydalanuvchi mavjud');
    }

    const newAdmin = await this.adminService.createAdmin(createAdminDto); // ✅
    // console.log(newAdmin);

    return { message: "Foydalanuvchi qo'shildi", adminId: newAdmin.id };
  }

  async signIn(signInDto: SignInDto, res: Response) {
    const admin = await this.adminService.findAdminByEmail(signInDto.email);
    if (!admin) {
      throw new BadRequestException("Email yoki password noto'g'ri");
    }

    // console.log('Password:', signInDto.password);
    // console.log('Hashed password:', staff);

    const isValidPassword = await bcrypt.compare(
      signInDto.password,
      admin.hashed_password,
    );
    if (!isValidPassword) {
      throw new BadRequestException("Email yoki password noto'g'ri");
    }

    const { accessToken, refreshToken } = await this.generateTokenAdmin(admin);
    res.cookie('refresh_token', refreshToken, {
      httpOnly: true,
      maxAge: Number(process.env.COOKIE_TIME),
    });
    admin.hashed_refresh_token = await bcrypt.hash(refreshToken, 7);
    await admin.save();
    res.status(200).send({
      message: 'Tizimga xush keleibsiz',
      refreshToken,
    });
  }

  async signOut(refreshToken: string, res: Response) {
    const adminData = await this.jwtService.verify(refreshToken, {
      secret: process.env.REFRESH_TOKEN_KEY,
    });

    if (!adminData) {
      throw new ForbiddenException('patient not verified');
    }
    const hashed_refresh_token = '';
    await this.adminService.updateRefreshToken(
      adminData.id,
      hashed_refresh_token,
    );

    res.clearCookie('refresh_token');
    const respnose = {
      message: 'staff logged out successfully',
    };
    return respnose;
  }

  async refreshToken(adminId: number, refresh_token: string, res: Response) {
    const decodeToken = await this.jwtService.decode(refresh_token);
    console.log(adminId);
    console.log(decodeToken['id']);

    if (adminId !== decodeToken['id']) {
      throw new ForbiddenException('Ruxsat etilmagan');
    }
    const admin = await this.adminService.findOneAdmin(adminId);

    // console.log('Hashed token:', staff?.hashed_refresh_token);

    if (!admin || !admin.hashed_refresh_token) {
      throw new NotFoundException('staff not found');
    }

    const tokenMatch = await bcrypt.compare(
      refresh_token,
      admin.hashed_refresh_token,
    );

    if (!tokenMatch) {
      throw new ForbiddenException('Forbidden');
    }
    const { accessToken, refreshToken } = await this.generateTokenAdmin(admin);

    const hashed_refresh_token = await bcrypt.hash(refreshToken, 7);
    await this.adminService.updateRefreshToken(admin.id, hashed_refresh_token);

    res.cookie('refresh_token', refreshToken, {
      maxAge: Number(process.env.COOKIE_TIME),
      httpOnly: true,
    });
    const respnose = {
      message: 'Staff refreshed',
      patientId: admin.id,
      access_token: accessToken,
    };
    return respnose;
  }
}