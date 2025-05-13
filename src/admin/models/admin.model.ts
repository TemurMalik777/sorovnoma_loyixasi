import { StdioNull } from "child_process";
import { Model, Table, Column, DataType } from "sequelize-typescript";



interface IAdminCreaterAttr {
  username: string;
  email: string;
  password: string;
  phone_number: string;
//   role: string
}

@Table({ tableName: "admins" })
export class Admin extends Model<Admin, IAdminCreaterAttr> {
  @Column({
    type: DataType.STRING,
    allowNull: false,
  })
  declare username: string;

  @Column({
    type: DataType.STRING,
    allowNull: false,
    unique: true,
  })
  declare email: string;

  @Column({
    type: DataType.STRING,
    allowNull: false,
  })
  declare hashed_password: string;

  @Column({
    type: DataType.STRING,
    allowNull: false,
    unique: true,
  })
  declare phone_number: string;

  @Column({
    type: DataType.BOOLEAN,
    defaultValue: false,
  })
  declare is_creater: boolean;

  @Column({
    type: DataType.BOOLEAN,
    allowNull: false,
  })
  declare is_active: boolean;

  @Column({
    type: DataType.TEXT,
    allowNull: true,
  })
  declare hashed_refresh_token: string;
}
