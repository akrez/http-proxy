<h1>راه‌اندازی فیلترشکن با هاست اشتراکی PHP</h1>

<h2>چرا از هاست اشتراکی PHP استفاده کنیم؟</h2>

<ul>
  <li>
    <strong> قیمت مناسب: </strong>
    <br />
    هاست‌های اشتراکی معمولاً هزینه‌ی بسیار کمتری نسبت به سرورهای اختصاصی دارند و
    این موضوع برای بسیاری از کاربران جذاب است.
  </li>

  <li>
    <strong> IP‌های تمیز: </strong>
    <br />
    هاست‌ها معمولاً از IP‌های تمیز و معتبر استفاده می‌کنند که می‌تواند در عملکرد
    بهتر فیلترشکن مؤثر باشد.
  </li>

  <li>
    <strong> پهنای باند نامحدود: </strong>
    <br />
    بسیاری از سرویس‌دهندگان هاستینگ پهنای باند نامحدود ارائه می‌دهند که این
    ویژگی برای فیلترشکن بسیار مناسب است، زیرا بدون نگرانی از محدودیت پهنای باند
    می‌توانید از اینترنت استفاده کنید.
  </li>

  <li>
    <strong> راه‌اندازی راحت‌تر: </strong>
    <br />
    مدیریت هاست اشتراکی و راه‌اندازی یک اسکریپت ساده PHP بسیار آسان‌تر از مدیریت
    سرور اختصاصی یا مجازی است.
  </li>
</ul>

<h2>چه مشکلاتی وجود دارد؟</h2>

<ul>
  <li>
    <strong> محدودیت پروتکل‌ها: </strong>
    <br />
    هاست‌های اشتراکی ممکن است فقط از پروتکل‌های محدودی پشتیبانی کنند که این
    موضوع می‌تواند عملکرد فیلترشکن را تحت تأثیر قرار دهد.
  </li>

  <li>
    <strong> مناسب نبودن برای موبایل: </strong>
    <br />
    این روش هنوز برای گوشی‌های همراه بهینه‌سازی نشده است و نیاز به توسعه بیشتری
    دارد.
  </li>

  <li>
    <strong> پیچیدگی برای کاربران عادی: </strong>
    <br />
    استفاده از این نوع فیلترشکن ممکن است برای کاربران عادی کمی گیج‌کننده باشد و
    نیاز به راهنمایی بیشتری داشته باشد.
  </li>
</ul>

<h2>چطور کار می‌کند؟</h2>

<p>
  به طور کلی این روش مشابه عملکرد یک <strong> HTTP Proxy </strong>
  است، اما به دلیل محدودیت‌ها، تفاوت‌هایی در نحوه اجرا وجود دارد:
</p>

<ol>
  <li>درخواست اصلی دستکاری می‌شود تا بتوان آن را به هاست پراکسی ارسال کرد.</li>

  <li>
    پس از رسیدن درخواست دستکاری‌شده به هاست پراکسی، درخواست اصلی بازیابی شده،
    پردازش می‌شود و پاسخ به کاربر بازگردانده می‌شود.
  </li>
</ol>

<code class="language-plaintext">
==OriginalRequest==>
(local http proxy server: manipulate request to change method and url)
==ManipulatedRequest==>
(proxy shared host: recover original request using script and resolve it and return response)
==Response==>
</code>

<h2>بیایید با یک مثال بررسی کنیم</h2>

<p>
  فرض کنید می‌خواهیم درخواست زیر را به آدرس
  <code> www.blocked.com/sensored/content.json </code>
  ارسال کنیم:
</p>

<code>
OPTIONS /sensored/content.json HTTP/1.1<br />
User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)<br />
Host: www.blocked.com<br />
Content-Type: application/json<br />
<br />
{ "name": "John Doe", "email": "john.doe@example.com" }<br />
</code>

<h3>محدودیت‌ها</h3>

<ul>
  <li>
    <strong> محدودیت در متد: </strong>
    <br />
    شاید متد اصلی (مانند <code> OPTIONS </code> ) روی هاست پشتیبانی نشود؛ پس
    باید قبل از ارسال، متد را به <code> POST </code>
    تغییر دهیم و در هاست، دوباره آن را بازیابی کنیم.
  </li>

  <li>
    <strong> هدر Host: </strong>
    <br />
    هدر <code> Host </code>
    درخواست اصلی با میزبان پراکسی متفاوت است و باید جایگزین شود.
  </li>
</ul>

<h2>پس چه راه‌حلی داریم؟</h2>

<p>آدرس درخواست را طوری تغییر می‌دهیم که به هاست پراکسی برسد. مثلاً:</p>

<div>
  <code>
  https://www.blocked.com/sensored/content.json
  </code>
</div>

<p>تبدیل می‌شود به:</p>

<code>
  <code>
  https://www.proxy-host.com/inline.php/https_OPTIONS/www.blocked.com/sensored/content.json

</code>

</code>

<p>
  پس در این حالت، درخواست زیر به جای درخواست اصلی (در این مثال یعنی درخواست
  بالا) ارسال می‌شود:
</p>

<code>
  <code class="language-http">
POST /inline.php/https_OPTIONS/www.blocked.com/sensored/content.json HTTP/1.1<br />
User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)<br />
Content-Type: application/json<br />
Host: www.proxy-host.com<br />
<br />
{ "name": "John Doe", "email": "john.doe@example.com" }
</code>

</code>

<h3>توضیح بخش‌های URL</h3>

<table>
  <thead>
    <tr>
      <th>بخش</th>

      <th>توضیح</th>
    </tr>
  </thead>

  <tbody>
    <tr>
      <td>
        <code> https://www.proxy-host.com/inline.php </code>
      </td>

      <td>
        مسیر اسکریپت روی هاست اشتراکی. می‌تواند به عنوان توکن برای هر کاربر نیز
        عمل کند. یعنی اسکریپت میتواند روی فایل
        <code> uncodedictable_personal_token.php </code>
        به جای <code> inline.php </code>
        هاست شود
      </td>
    </tr>

    <tr>
      <td>
        <code> https_OPTIONS </code>
      </td>

      <td>
        بخش کانفیگ: پروتکل و متد. با <code> _ </code> جدا می‌شوند و اختیاری‌اند.
        می‌توانید <code> debug </code> هم اضافه کنید (<code>
          https_OPTIONS_debug
        </code>
        ).
      </td>
    </tr>

    <tr>
      <td>
        <code> www.blocked.com/sensored/content.json </code>
      </td>

      <td>آدرس اصلی درخواست همراه با تمام پارامترها.</td>
    </tr>
  </tbody>
</table>

<h2>آیا باید دستی URL‌ها را تغییر دهیم؟</h2>

<p>
  خیر. برای این کار از <strong> MitmProxy </strong> استفاده می‌کنیم تا
  درخواست‌ها به صورت خودکار دستکاری شوند. فایل‌های مورد نیاز در مسیر
  <code> client/inline.py </code>
  قرار دارند.
</p>

<h3>مراحل نصب و راه‌اندازی</h3>

<ol>
  <li>
    <p>ریپوزیتوری را کلون کنید تا فایل‌ها را در اختیار داشته باشید.</p>
  </li>

  <li>
    <p>
      یکی از نسخه‌های پرتابل MitmProxy را از<br />
      <a href="https://www.mitmproxy.org/downloads/">
        https://www.mitmproxy.org/downloads/
      </a>
      دانلود کرده و فایل
      <code> mitmdump.exe </code>
      را به پوشه <code> client </code>
      منتقل کنید.
    </p>
  </li>

  <li>
    <p>گواهی‌های MitmProxy را نصب کنید:</p>

    <ul>
      <li>
        <p>
          یک بار <code> mitmdump.exe </code>
          را اجرا کنید تا فایل‌های گواهی ایجاد شوند.
        </p>
      </li>

      <li>
        <p>سپس دستور زیر را اجرا کنید:</p>

        <code>
          <code class="language-bash">
            certutil -addstore root "%USERPROFILE%\.mitmproxy\mitmproxy-ca-cert.cer"
          </code>
        
        </code>
      </li>

      <li>
        <p>برای مرورگر Firefox مراحل اضافی را طبق راهنما انجام دهید.</p>
      </li>
    </ul>
  </li>

  <li>
    <p>
      فایل <code> config.ini.default </code> را به <code> config.ini </code>
      تغییر نام داده و مقادیر زیر را ویرایش کنید:
    </p>

    <code>
      <code class="language-ini">
[inline]<br />
url=https://proxy-php-host.com/inline.php<br />
; host_header=proxy-php-host.com
      </code>
    </code>
    <p>در صورت استفاده از IP:</p>
    <code>
      <code class="language-ini">
[inline]<br />
url=https://100.100.100.100/inline.php<br />
host_header=proxy-php-host.com
      </code>
    </code>
  </li>

  <li>
    <p>MitmProxy را با پارامترهای زیر اجرا کنید:</p>

    <code>
      <code class="language-bash">
      .\mitmdump.exe -q -s inline.py \
  --set listen_port=8080 \
  --set flow_detail=0 \
  --set connection_strategy=lazy \
  --set ssl_insecure=true \
  --set stream_large_bodies=128k

</code>

</code>
  </li>

  <li>
    <p>
      تمام شد! در تنظیمات سیستم ویندوز، پراکسی را روی <code> 127.0.0.1 </code> و
      پورت را برابر <code> listen_port </code>

      (اینجا 8080) قرار دهید. 🎉
    </p>
  </li>
</ol>

<p>```</p>
