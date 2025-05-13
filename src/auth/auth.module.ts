import { Module } from "@nestjs/common";
import { JwtModule } from "@nestjs/jwt";
import { AdminModule } from "../admin/admin.module";
import { AuthController } from "./admin/auth.controller";
import { AuthService } from "./admin/auth.service";

@Module({
  imports: [
    JwtModule.register({
      global: true,
    }),
    AdminModule,
  ],
  controllers: [AuthController],
  providers: [AuthService],
  exports: [AuthService],
})
export class AuthModule {}
