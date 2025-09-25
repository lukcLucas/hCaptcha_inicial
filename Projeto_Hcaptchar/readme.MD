bora deixar isso redondo no Angular. Aqui vai um componente **Login** com **reCAPTCHA v2 (checkbox)** usando `HttpClient` + **Reactive Forms**, renderizando o widget via `grecaptcha.render`, pegando o token com `grecaptcha.getResponse(widgetId)` e resetando com `grecaptcha.reset(widgetId)`.

### 1) environment

```ts
// src/environments/environment.ts
export const environment = {
  production: false,
  apiBase: 'http://localhost:5000',
  recaptchaSiteKey: 'YOUR_RECAPTCHA_SITE_KEY'
};
```

### 2) Tipagem do grecaptcha

```ts
// src/typings.d.ts
declare var grecaptcha: any;
```

### 3) Módulo da aplicação (imports básicos)

```ts
// src/app/app.module.ts
import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { ReactiveFormsModule } from '@angular/forms';
import { HttpClientModule, HTTP_INTERCEPTORS } from '@angular/common/http';

import { AppComponent } from './app.component';
import { LoginComponent } from './login/login.component';
import { AuthInterceptor } from './core/auth.interceptor';

@NgModule({
  declarations: [AppComponent, LoginComponent],
  imports: [BrowserModule, ReactiveFormsModule, HttpClientModule],
  providers: [{ provide: HTTP_INTERCEPTORS, useClass: AuthInterceptor, multi: true }],
  bootstrap: [AppComponent]
})
export class AppModule {}
```

### 4) Interceptor para JWT (opcional, mas prático)

```ts
// src/app/core/auth.interceptor.ts
import { Injectable } from '@angular/core';
import { HttpInterceptor, HttpRequest, HttpHandler, HttpEvent } from '@angular/common/http';
import { Observable } from 'rxjs';

@Injectable()
export class AuthInterceptor implements HttpInterceptor {
  intercept(req: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
    const jwt = localStorage.getItem('jwt');
    if (jwt) {
      req = req.clone({ setHeaders: { Authorization: `Bearer ${jwt}` } });
    }
    return next.handle(req);
  }
}
```

### 5) Serviço de autenticação

```ts
// src/app/core/auth.service.ts
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../environments/environment';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private base = environment.apiBase;

  constructor(private http: HttpClient) {}

  async login(email: string, password: string, recaptchaToken: string) {
    const formData = new FormData();
    formData.set('email', email);
    formData.set('password', password);
    // reCAPTCHA v2 envia g-recaptcha-response, então o backend deve ler esse campo
    formData.set('g-recaptcha-response', recaptchaToken);

    const data: any = await this.http.post(`${this.base}/api/login`, formData).toPromise();
    if (data?.ok && data?.token) localStorage.setItem('jwt', data.token);
    return data;
  }

  profile() {
    return this.http.get(`${this.base}/api/profile`);
  }

  logout() {
    localStorage.removeItem('jwt');
  }
}
```

### 6) Componente Angular (TS)

```ts
// src/app/login/login.component.ts
import { Component, ElementRef, ViewChild, AfterViewInit } from '@angular/core';
import { FormBuilder, Validators } from '@angular/forms';
import { AuthService } from '../core/auth.service';
import { environment } from '../../environments/environment';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent implements AfterViewInit {
  siteKey = environment.recaptchaSiteKey;
  loading = false;
  showPass = false;
  status: { text: string; kind?: 'ok' | 'err' } | null = null;
  output: any = null;

  @ViewChild('captchaElem', { static: true }) captchaElem!: ElementRef<HTMLDivElement>;
  private widgetId: number | null = null;

  form = this.fb.group({
    email: ['', [Validators.required, Validators.email]],
    password: ['', [Validators.required]]
  });

  constructor(private fb: FormBuilder, private auth: AuthService) {}

  ngAfterViewInit(): void {
    this.ensureRecaptchaScript().then(() => this.renderCaptcha());
  }

  private ensureRecaptchaScript(): Promise<void> {
    // Se o script já está presente, resolve
    if ((window as any).grecaptcha?.render) return Promise.resolve();

    return new Promise<void>((resolve, reject) => {
      const id = 'recaptcha-api';
      if (document.getElementById(id)) return resolve();

      const s = document.createElement('script');
      s.id = id;
      s.src = 'https://www.google.com/recaptcha/api.js?render=explicit';
      s.async = true;
      s.defer = true;
      s.onload = () => resolve();
      s.onerror = () => reject(new Error('Falha ao carregar reCAPTCHA.'));
      document.head.appendChild(s);
    });
  }

  private renderCaptcha() {
    const g = (window as any).grecaptcha;
    if (!g?.render) return;

    this.widgetId = g.render(this.captchaElem.nativeElement, {
      sitekey: this.siteKey,
      theme: this.prefersDark() ? 'dark' : 'light'
    });
  }

  private prefersDark() {
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  }

  togglePassword() {
    this.showPass = !this.showPass;
  }

  async submit() {
    this.status = { text: 'Enviando login...' };
    this.output = null;

    if (this.form.invalid) {
      this.status = { text: 'Preencha e-mail e senha.', kind: 'err' };
      return;
    }

    const g = (window as any).grecaptcha;
    if (!g || this.widgetId === null) {
      this.status = { text: 'reCAPTCHA não carregou.', kind: 'err' };
      return;
    }

    const token = g.getResponse(this.widgetId);
    if (!token) {
      this.status = { text: 'Complete o reCAPTCHA.', kind: 'err' };
      return;
    }

    this.loading = true;
    try {
      const { email, password } = this.form.value as { email: string; password: string };
      const data = await this.auth.login(email, password, token);
      if (data?.ok) {
        this.status = { text: '✅ Logado com sucesso!', kind: 'ok' };
      } else {
        this.status = { text: '❌ ' + (data?.error || 'Falha no login.'), kind: 'err' };
      }
      this.output = data;
    } catch (e) {
      this.status = { text: '❌ Erro de rede.', kind: 'err' };
    } finally {
      this.loading = false;
      try { g.reset(this.widgetId); } catch {}
    }
  }

  async callProfile() {
    this.status = { text: 'Chamando /api/profile...' };
    this.output = null;
    try {
      const data = await this.auth.profile().toPromise();
      this.status = { text: '✅ OK', kind: 'ok' };
      this.output = data;
    } catch {
      this.status = { text: '❌ Erro', kind: 'err' };
    }
  }

  logout() {
    this.auth.logout();
    this.status = { text: 'Sessão encerrada.', kind: 'ok' };
    this.output = null;
  }
}
```

### 7) Template (HTML)

```html
<!-- src/app/login/login.component.html -->
<main class="card" aria-labelledby="title">
  <div class="glow"></div>
  <header>
    <div class="logo" aria-hidden="true"></div>
    <div>
      <h1 id="title">Bem-vindo de volta</h1>
      <p class="sub">Acesse sua conta com proteção por reCAPTCHA</p>
    </div>
  </header>

  <form [formGroup]="form" (ngSubmit)="submit()" novalidate>
    <div class="field">
      <label class="label" for="email">E-mail</label>
      <div class="input">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M4 8l8 5 8-5"/><rect x="3" y="5" width="18" height="14" rx="2"/></svg>
        <input id="email" type="email" formControlName="email" placeholder="seu@email.com"
               autocomplete="email" required />
      </div>
    </div>

    <div class="field">
      <label class="label" for="password">Senha</label>
      <div class="input">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="3" y="11" width="18" height="10" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        <input [type]="showPass ? 'text' : 'password'" id="password" formControlName="password"
               placeholder="••••••••" autocomplete="current-password" required />
        <button type="button" class="icon" (click)="togglePassword()" aria-label="Mostrar/ocultar senha">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
            <ng-container *ngIf="!showPass; else eyeOff">
              <path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z"/><circle cx="12" cy="12" r="3"/>
            </ng-container>
            <ng-template #eyeOff>
              <path d="M17.94 17.94A10.94 10.94 0 0 1 12 20c-7 0-11-8-11-8a20.29 20.29 0 0 1 5.06-6.94M9.9 4.24A10.94 10.94 0 0 1 12 4c7 0 11 8 11 8a20.35 20.35 0 0 1-4.07 5.14M1 1l22 22M9.9 9.9A3 3 0 0 0 12 9c1.66 0 3 1.34 3 3a3 3 0 0 0-.9 2.1"/>
            </ng-template>
          </svg>
        </button>
      </div>
    </div>

    <div class="field">
      <div class="row">
        <span class="label">Verificação</span>
        <span class="muted">Protegido por reCAPTCHA</span>
      </div>
      <!-- o widget será renderizado aqui via grecaptcha.render -->
      <div #captchaElem class="g-recaptcha"></div>
    </div>

    <div class="row">
      <button class="btn" type="submit" [disabled]="loading">Entrar</button>
      <div class="actions">
        <button type="button" class="btn btn-ghost" (click)="callProfile()">/api/profile</button>
        <button type="button" class="btn btn-ghost" (click)="logout()">Sair</button>
      </div>
    </div>

    <div role="status" aria-live="polite" class="muted" [ngClass]="{'alert': status, 'ok': status?.kind==='ok', 'err': status?.kind==='err'}">
      {{ status?.text }}
    </div>

    <pre *ngIf="output">{{ output | json }}</pre>
  </form>
</main>
```

### 8) Estilos (SCSS) — o mesmo look & feel do seu HTML

```scss
/* src/app/login/login.component.scss */
:root{
  --bg:#0b0f1a; --card:rgba(255,255,255,.08); --card-border:rgba(255,255,255,.14);
  --text:#e6e8ee; --muted:#bac1d4; --primary:#7c5cff; --primary-700:#6746ff;
  --ring:rgba(124,92,255,.45); --error:#ff5470; --ok:#1ec28b; --shadow:0 10px 30px rgba(0,0,0,.35);
}
@media (prefers-color-scheme: light){
  :root{ --bg:#f6f7fb; --card:#fff; --card-border:#e6e8f0; --text:#0b1220; --muted:#4c5465;
         --ring:rgba(124,92,255,.35); --shadow:0 10px 30px rgba(21,23,35,.08); }
}
:host { display: grid; place-items: center; min-height: 100dvh; padding: 2rem; background: var(--bg); }
.card{ width:min(560px,100%); border:1px solid var(--card-border);
  background:linear-gradient(180deg, color-mix(in oklab, var(--card), white 3%), var(--card));
  backdrop-filter: blur(10px); border-radius:20px; padding:1.5rem; box-shadow:var(--shadow);
  position:relative; overflow:hidden;
}
.glow{ position:absolute; inset:-40% -10% auto auto; width:420px; height:420px; filter: blur(60px);
  background:conic-gradient(from 200deg, rgba(124,92,255,.25), rgba(30,194,139,.22), transparent 40%);
  pointer-events:none;
}
header{display:flex; align-items:center; gap:.75rem; margin-bottom:1rem}
.logo{width:36px; height:36px; border-radius:10px;
  background: radial-gradient(closest-side,#fff 0 40%,transparent 41%),
              conic-gradient(var(--primary),#20d198,#00bcd4,var(--primary));
  box-shadow:0 6px 16px rgba(124,92,255,.35);
}
h1{font-size:1.35rem; margin:0}
.sub{margin:.15rem 0 0; color:var(--muted); font-size:.95rem}
form{display:grid; gap:1rem; margin-top:.75rem}
.field{display:grid; gap:.4rem}
.label{font-weight:600; font-size:.92rem}
.input{display:flex; align-items:center; gap:.55rem; border:1px solid var(--card-border); background:#0000; border-radius:12px; padding:.75rem .9rem; transition:.2s ease;
  outline:none; box-shadow:0 0 0 0 var(--ring);
  &:focus-within{border-color:color-mix(in oklab,var(--primary),#fff 12%); box-shadow:0 0 0 6px var(--ring)}
  input{all:unset; flex:1; min-width:0}
  .icon{all:unset; cursor:pointer; border-radius:8px; padding:.35rem; display:grid; place-items:center}
  svg{width:18px; height:18px}
}
.row{display:flex; gap:.75rem; align-items:center; justify-content:space-between; flex-wrap:wrap}
.btn{appearance:none; border:0; cursor:pointer; padding:.9rem 1rem; border-radius:12px; font-weight:700; letter-spacing:.2px;
  background:linear-gradient(180deg,var(--primary) 0%, var(--primary-700) 100%);
  color:#fff; box-shadow:0 10px 20px rgba(124,92,255,.35), inset 0 -2px 0 rgba(0,0,0,.2);
  transition: transform .08s ease, filter .2s ease, box-shadow .2s ease;
  &:active{transform:translateY(1px)} &:disabled{opacity:.6; cursor:not-allowed; filter:saturate(.6)}
}
.btn-ghost{background:transparent; color:var(--text); border:1px solid var(--card-border); box-shadow:none; font-weight:600}
.actions{display:flex; gap:.6rem; flex-wrap:wrap}
.muted{color:var(--muted); font-size:.92rem}
.alert{border-radius:12px; padding:.75rem .9rem; font-weight:600}
.ok{background: color-mix(in oklab,var(--ok), transparent 80%); border:1px solid color-mix(in oklab,var(--ok), #000 20%)}
.err{background: color-mix(in oklab,var(--error), transparent 85%); border:1px solid color-mix(in oklab,var(--error), #000 20%)}
pre{background:color-mix(in oklab,var(--card), white 4%); border:1px dashed var(--card-border); padding:1rem; border-radius:12px; overflow:auto; margin:0}
```

### 9) `index.html` (opcional)

Se preferir, pode **não** carregar o script dinamicamente e sim no `index.html`:

```html
<!-- src/index.html -->
<script src="https://www.google.com/recaptcha/api.js?render=explicit" async defer></script>
```

Se fizer isso, pode remover o método `ensureRecaptchaScript()` e chamar `renderCaptcha()` direto no `ngAfterViewInit`.

---

### Como funciona o fluxo

1. O componente renderiza o widget reCAPTCHA **explicit** via `grecaptcha.render(...)`.
2. No submit, busca o token com `grecaptcha.getResponse(widgetId)`.
3. Envia `email`, `password` e **`g-recaptcha-response`** para `POST /api/login`.
4. Se o backend retornar `{ ok: true, token }`, salva no `localStorage` e o interceptor passa a enviar `Authorization: Bearer <token>`.
5. Botões “/api/profile” e “Sair” usam o service.

