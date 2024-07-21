import { ForbiddenException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';

import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async signup(data: AuthDto) {
    // Kita genrate atau encryption si password
    const hash = await argon.hash(data.password);

    // Simpan data ke database jika password sudah di encryption
    try {
      const user = await this.prismaService.user.create({
        data: {
          email: data.email,
          password: hash,
        },
      });

      // kita harus ngasih token, caranya??? bikin method
      return await this.signToken(user.id, user.email);
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          //kode error duplicate
          throw new ForbiddenException('Credentials has already taken!');
        }
      }
    }
  }

  async signin(data: AuthDto) {
    const isUserExist = await this.prismaService.user.findUnique({
      where: {
        email: data.email,
      },
    });

    // Jika user tidak ada
    if (!isUserExist) throw new ForbiddenException('User does not exist!');

    // Kita harus verifikasi password nya benar atau ngga?

    // ini formatnya string
    const passwordFromUser = data.password;
    // Ini formatnya hash dalam bentuk argon
    const passwordFromDatabase = isUserExist.password;

    // komparasi dengan argon
    const isPasswordMatch = await argon.verify(
      passwordFromDatabase,
      passwordFromUser,
    );

    if (!isPasswordMatch) throw new ForbiddenException('Wrong password!');

    return await this.signToken(isUserExist.id, isUserExist.email);
  }

  // Ini untuk membuat token
  async signToken(userId: number, email: string) {
    // Bikin payload untuk Jwt
    const payload = {
      sub: userId,
      email,
    };

    // Baca environment variable si secretnya atau signature nya
    const secretJwt = this.configService.get('JWT_SECRET');

    const token = await this.jwtService.signAsync(payload, {
      algorithm: 'HS256',
      expiresIn: '15m',
      secret: secretJwt,
    });

    return {
      access_token: token,
    };
  }
}
