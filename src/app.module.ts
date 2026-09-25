import { Module } from '@nestjs/common';
import { BuController } from './bu.controller';
import { BuService } from './bu.service';

@Module({
  controllers: [BuController],
  providers: [BuService],
})
export class AppModule {}
