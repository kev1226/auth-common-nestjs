// src/guards/auth.guard.ts
import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  ForbiddenException,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { JwtService } from "@nestjs/jwt";
import { ROLES_KEY } from "../decorators/auth.decorator";

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly jwtService: JwtService,
    private readonly reflector: Reflector
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const roles = this.reflector.get<string[]>(ROLES_KEY, context.getHandler());

    if (!roles) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const token = request.headers["authorization"]?.split(" ")[1];

    if (!token) {
      throw new UnauthorizedException("Token no encontrado");
    }

    try {
      const decoded = await this.jwtService.verifyAsync(token);
      request.user = decoded;

      const hasRole = roles.some((role: string) =>
        decoded.roles.includes(role)
      );

      if (!hasRole) {
        throw new ForbiddenException(
          "No tienes permisos para acceder a este recurso"
        );
      }

      return true;
    } catch (error) {
      throw new UnauthorizedException("Token inválido o expirado");
    }
  }
}
