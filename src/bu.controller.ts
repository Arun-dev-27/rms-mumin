import { Body, Controller, Get, Post, Query, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import { BuService } from './bu.service';
import { esc, homePage, landingPage, messagePage } from './views';

@Controller()
export class BuController {
  constructor(private readonly bu: BuService) {}

  @Get()
  home(@Req() req: Request, @Res() res: Response) {
    const b = this.bu.browser(req, res);
    res.set('cache-control', 'no-store').type('html').send(homePage(b, this.bu.backchannelDown, this.bu.hasSecret()));
  }

  @Get('api/version')
  version(@Req() req: Request, @Res() res: Response) {
    res.set('cache-control', 'no-store').json({ version: this.bu.browser(req, res).version });
  }

  @Get('clear')
  clear(@Req() req: Request, @Res() res: Response) {
    this.bu.clear(this.bu.browser(req, res));
    res.redirect(303, '/');
  }

  // ---- sign in ----------------------------------------------------------------------------------

  @Get('login')
  login(@Req() req: Request, @Res() res: Response, @Query('acr') acr?: string, @Query('max_age') maxAge?: string) {
    const b = this.bu.browser(req, res);
    try {
      res.redirect(302, this.bu.startLogin(b, acr, maxAge));
    } catch (error) {
      this.bu.fail(b, error instanceof Error ? error.message : String(error));
      res.redirect(303, '/');
    }
  }

  @Get('auth/callback')
  async callback(@Req() req: Request, @Res() res: Response, @Query() query: Record<string, string | undefined>) {
    const b = this.bu.browser(req, res);
    const next = await this.bu.finishLogin(b, query).catch((error: unknown) => {
      this.bu.fail(b, error instanceof Error ? error.message : String(error));
      return '/';
    });
    res.redirect(303, next);
  }

  // ---- logout -----------------------------------------------------------------------------------

  @Get('logout')
  logout(@Req() req: Request, @Res() res: Response) {
    res.redirect(302, this.bu.startLogout(this.bu.browser(req, res)));
  }

  @Get('logged-out')
  loggedOut(@Req() req: Request, @Res() res: Response, @Query('state') state?: string) {
    this.bu.loggedOut(this.bu.browser(req, res), state);
    res.redirect(303, '/');
  }

  /** Back-channel logout endpoint: Core calls it server to server (form-encoded logout_token). */
  @Post('auth/core/logout')
  async backchannel(@Body('logout_token') logoutToken: string | undefined, @Res() res: Response) {
    const status = await this.bu.backchannelLogout(logoutToken ?? '');
    const body = status === 200 ? { ok: true } : status === 503 ? { error: 'unavailable' } : { error: 'invalid_logout_token' };
    res.status(status).json(body);
  }

  @Post('api/backchannel')
  setBackchannel(@Req() req: Request, @Res() res: Response, @Body('down') down?: string) {
    this.bu.setBackchannelDown(this.bu.browser(req, res), down === '1');
    res.status(204).end();
  }

  // ---- trusted handoff --------------------------------------------------------------------------

  /** SOURCE side: this app asks Core for a handoff, then sends the browser to the one-time Core URL. */
  @Get('handoff')
  async handoff(@Req() req: Request, @Res() res: Response, @Query('target') target?: string, @Query('path') path?: string) {
    const b = this.bu.browser(req, res);
    const url = await this.bu.startHandoff(b, target, path).catch((error: unknown) => {
      this.bu.fail(b, error instanceof Error ? error.message : String(error));
      return null;
    });
    res.redirect(303, url ?? '/');
  }

  /** TARGET side: Core auto-posts the signed one-time assertion here. */
  @Post('auth/core/handoff')
  async handoffIn(@Req() req: Request, @Res() res: Response, @Body('assertion') assertion?: string) {
    const b = this.bu.browser(req, res);
    const result = await this.bu.verifyHandoff(assertion ?? '');
    res.set('cache-control', 'no-store');
    if (!result.ok) {
      this.bu.event(b, `Handoff REJECTED: ${result.code}`, false);
      return res.status(400).type('html').send(messagePage('Could not open this page', `<p class="err">${esc(result.code)}</p>`));
    }
    const c = result.claims;
    if (result.denied) {
      this.bu.event(b, `Handoff verified for ITS ${String(c.sub)} but ${String(c.requested_path)} DENIED by local authorization (no local session created)`, false);
      return res
        .status(403)
        .type('html')
        .send(messagePage('Access denied', `<p>You are signed in as ITS ${esc(c.sub)}, but you do not have permission for <code>${esc(c.requested_path)}</code> here.</p>`));
    }
    this.bu.acceptHandoff(b, c, result.kid);
    res.redirect(303, String(c.requested_path));
  }

  /** Landing pages a handoff opens. */
  @Get(['dashboard', 'dashboard/*rest', 'events/*rest', 'bookings/*rest', 'admin/*rest'])
  landing(@Req() req: Request, @Res() res: Response) {
    const b = this.bu.browser(req, res);
    if (!b.session) return res.redirect(303, '/');
    res.set('cache-control', 'no-store').type('html').send(landingPage(b, req.originalUrl));
  }
}
