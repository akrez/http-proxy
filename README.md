<div dir="rtl">

# راه‌اندازی فیلترشکن با هاست اشتراکی PHP

## چرا از هاست اشتراکی PHP استفاده کنیم؟

- **قیمت مناسب:**  
  هاست‌های اشتراکی معمولاً هزینه‌ی بسیار کمتری نسبت به سرورهای اختصاصی دارند و این موضوع برای بسیاری از
  کاربران جذاب است.
- **IP‌های تمیز:**  
  هاست‌ها معمولاً از IP‌های تمیز و معتبر استفاده می‌کنند که می‌تواند در عملکرد بهتر فیلترشکن مؤثر باشد.
- **پهنای باند نامحدود:**  
  بسیاری از سرویس‌دهندگان هاستینگ پهنای باند نامحدود ارائه می‌دهند که این ویژگی برای فیلترشکن بسیار مناسب است،
  زیرا بدون نگرانی از محدودیت پهنای باند می‌توانید از اینترنت استفاده کنید.
- **راه‌اندازی راحت‌تر:**  
  مدیریت هاست اشتراکی و راه‌اندازی یک اسکریپت ساده PHP بسیار آسان‌تر از مدیریت سرور اختصاصی یا مجازی است.

## چه مشکلاتی وجود دارد؟

- **محدودیت پروتکل‌ها:**  
  هاست‌های اشتراکی ممکن است فقط از پروتکل‌های محدودی پشتیبانی کنند که این موضوع می‌تواند عملکرد فیلترشکن را
  تحت تأثیر قرار دهد.
- **مناسب نبودن برای موبایل:**  
  این روش هنوز برای گوشی‌های همراه بهینه‌سازی نشده است و نیاز به توسعه بیشتری دارد.
- **پیچیدگی برای کاربران عادی:**  
  استفاده از این نوع فیلترشکن ممکن است برای کاربران عادی کمی گیج‌کننده باشد و نیاز به راهنمایی بیشتری داشته
  باشد.

## چطور کار می‌کند؟

به طور کلی این روش مشابه عملکرد یک **HTTP Proxy** است، اما به دلیل محدودیت‌ها، تفاوت‌هایی در نحوه اجرا وجود دارد:

1. درخواست اصلی دستکاری می‌شود تا بتوان آن را به هاست پراکسی ارسال کرد.
2. پس از رسیدن درخواست دستکاری‌شده به هاست پراکسی، درخواست اصلی بازیابی شده، پردازش می‌شود و پاسخ به کاربر
   بازگردانده می‌شود.

```ini
==OriginalRequest==>
(local http proxy server: manipulate request to change method and url)
==ManipulatedRequest==>
(proxy shared host: recover original request using script and resolve it and return response)
==Response==>
```

## بیایید با یک مثال بررسی کنیم

فرض کنید می‌خواهیم درخواست زیر را به آدرس `www.blocked.com/sensored/content.json` ارسال کنیم:

```ini
OPTIONS /sensored/content.json HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)
Host: www.blocked.com
Content-Type: application/json

{ "name": "John Doe", "email": "john.doe@example.com" }
```

### محدودیت‌ها

- **محدودیت در متد:**  
  شاید متد اصلی (مانند `OPTIONS`) روی هاست پشتیبانی نشود؛ پس باید قبل از ارسال، متد را به `POST` تغییر دهیم
  و در هاست، دوباره آن را بازیابی کنیم.
- **هدر Host:**  
  هدر `Host` درخواست اصلی با میزبان پراکسی متفاوت است و باید جایگزین شود.

### پس چه راه‌حلی داریم؟

آدرس درخواست را طوری تغییر می‌دهیم که به هاست پراکسی برسد. مثلاً:

```ini
https://www.blocked.com/sensored/content.json
```

تبدیل می‌شود به:

```ini
https://www.proxy-host.com/inline.php/https_OPTIONS/www.blocked.com/sensored/content.json
```

پس در این حالت، درخواست زیر به جای درخواست اصلی (در این مثال یعنی درخواست بالا) ارسال می‌شود:

```http
POST /inline.php/https_OPTIONS/www.blocked.com/sensored/content.json HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)
Content-Type: application/json
Host: www.proxy-host.com

{ "name": "John Doe", "email": "john.doe@example.com" }
```

### توضیح بخش‌های URL

| بخش                                     | توضیح                                                                                                                                                                          |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `https://www.proxy-host.com/inline.php` | مسیر اسکریپت روی هاست اشتراکی. می‌تواند به عنوان توکن برای هر کاربر نیز عمل کند. یعنی اسکریپت میتواند روی فایل `unpredictable_personal_token.php` به جای `inline.php` هاست شود |
| `https_OPTIONS`                         | بخش کانفیگ: پروتکل و متد. با `_` جدا می‌شوند و اختیاری‌اند. می‌توانید `debug` هم اضافه کنید (`https_OPTIONS_debug`).                                                           |
| `www.blocked.com/sensored/content.json` | آدرس اصلی درخواست همراه با تمام پارامترها.                                                                                                                                     |

## آیا باید دستی URL‌ها را تغییر دهیم؟

خیر. برای این کار از **MitmProxy** استفاده می‌کنیم تا درخواست‌ها به صورت خودکار دستکاری شوند. فایل‌های مورد نیاز
در مسیر `client/inline.py` قرار دارند.

### مراحل نصب و راه‌اندازی

1. ریپوزیتوری را کلون کنید تا فایل‌ها را در اختیار داشته باشید.
2. یکی از نسخه‌های پرتابل MitmProxy را از  
   <https://www.mitmproxy.org/downloads/> دانلود کرده و فایل `mitmdump.exe` را به پوشه `client` منتقل کنید.
3. گواهی‌های MitmProxy را نصب کنید:

   - یک بار `mitmdump.exe` را اجرا کنید تا فایل‌های گواهی ایجاد شوند.
   - سپس دستور زیر را اجرا کنید:

     ```bash
     certutil -addstore root "%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer"
     ```

   - برای مرورگر Firefox مراحل اضافی را طبق راهنما انجام دهید.

4. فایل `config.ini.default` را به `config.ini` تغییر نام داده و مقادیر زیر را ویرایش کنید:

   ```ini
   [inline]
   url=https://proxy-php-host.com/inline.php
   ; host_header=proxy-php-host.com
   ```

   در صورت استفاده از IP:

   ```ini
   [inline]
   url=https://100.100.100.100/inline.php
   host_header=proxy-php-host.com
   ```

5. MitmProxy را با پارامترهای زیر اجرا کنید:

   ```bash
   .\mitmdump.exe -q -s inline.py \
     --set listen_port=8080 \
     --set flow_detail=0 \
     --set connection_strategy=lazy \
     --set ssl_insecure=true \
     --set stream_large_bodies=128k
   ```

6. تمام شد! در تنظیمات سیستم ویندوز، پراکسی را روی `127.0.0.1` و پورت را برابر `listen_port` (اینجا 8080) قرار دهید. 🎉

</div>
