import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from "@nestjs/common";
import { CreateAdminDto } from "./dto/create-admin.dto";
import { UpdateAdminDto } from "./dto/update-admin.dto";
import { InjectModel } from "@nestjs/sequelize";
import { Admin } from "./models/admin.model";

import * as bcrypt from "bcrypt";

@Injectable()
export class AdminService {
  constructor(@InjectModel(Admin) private readonly adminModule: typeof Admin) {}

  async createAdmin(createAdminDto: CreateAdminDto): Promise<Admin> {
    const hashedPassword = await bcrypt.hash(createAdminDto.password, 7);
    const admin = await this.adminModule.create({
      ...createAdminDto,
      password: hashedPassword,
    });
    return admin;
  }

  findAdminByEmail(email: string) {
    return this.adminModule.findOne({ where: { email } });
  }

  async findAllAdmins(): Promise<Admin[]> {
    return this.adminModule.findAll({ include: { all: true } });
  }

  async findOneAdmin(id: number): Promise<Admin | null> {
    return this.adminModule.findByPk(id);
  }

  async updateAdmin(
    id: number,
    updateAdminDto: UpdateAdminDto
  ): Promise<Admin | null> {
    const updated = await this.adminModule.update(updateAdminDto, {
      where: { id },
      returning: true,
    });

    return updated[1][0]; // update() returns [affectedCount, affectedRows]
  }

  async removeAdmin(id: number): Promise<string> {
    const deleted = await this.adminModule.destroy({
      where: { id },
    });

    if (deleted > 0) {
      return "Admin o'chirildi";
    }
    return "Bunday Admin mavjud emas";
  }

  async updateRefreshToken(id: number, hashed_refresh_token: string) {
    const updateAdmin = await this.adminModule.update(
      { hashed_refresh_token },
      { where: { id } }
    );
    return updateAdmin;
  }

  async updateAdminPassword(
    id: number,
    dto: { oldPassword: string; newPassword: string }
  ): Promise<string> {
    const admin = await this.adminModule.findByPk(id);
    if (!admin) throw new NotFoundException("admin topilmadi");

    const isMatch = await bcrypt.compare(
      dto.oldPassword,
      admin.hashed_password
    );
    if (!isMatch) throw new BadRequestException("Eski parol notogri");

    const hashedNewPassword = await bcrypt.hash(dto.newPassword, 7);
    admin.hashed_password = hashedNewPassword;
    await admin.save();

    return "Parol muvaffaqiyatli yangilandi";
  }
}
