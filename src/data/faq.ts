export interface FaqItem {
  q: string;
  /** Plain text (also used for the FAQPage structured data). */
  a: string;
}

export const FAQ: FaqItem[] = [
  {
    q: 'What is X-Frame-Options?',
    a: 'X-Frame-Options is an HTTP response header that tells browsers whether a page may be shown inside a frame on another site. DENY blocks every site, including the page’s own. SAMEORIGIN allows only pages on the same origin (same scheme, host and port). ALLOW-FROM was meant to allow one named site, but it is obsolete: Chrome, Edge, Firefox and Safari ignore it, so it restricts nothing. The header only works when sent by the server — browsers ignore it in a <meta> tag.',
  },
  {
    q: 'What is frame-ancestors?',
    a: 'frame-ancestors is a Content-Security-Policy directive that lists which sites may embed a page. frame-ancestors \'none\' blocks everyone, \'self\' allows only the page’s own origin, and a list such as https://partner.com *.example.com allows exactly those sites. It replaces X-Frame-Options: when a page sends both, browsers follow frame-ancestors and ignore X-Frame-Options. Like X-Frame-Options it only works as an HTTP header, and a Content-Security-Policy-Report-Only version only reports violations without blocking.',
  },
  {
    q: 'Why do some sites block iframes?',
    a: 'Mainly to prevent clickjacking — an attacker could load a bank, email or social network invisibly inside their own page and trick you into clicking buttons you can’t see. Sites also block framing to protect logins and payments, keep their branding and ads intact, stop other sites from passing their content off as their own, and because third-party cookies are limited inside frames, which breaks signed-in features.',
  },
  {
    q: 'Why does a site work in a browser but not in an iframe?',
    a: 'Opening a page directly makes it the top-level page, so framing rules don’t apply. Inside an iframe on another site the browser checks the page’s X-Frame-Options and CSP frame-ancestors headers first, and shows an error such as “refused to connect” if they don’t allow your site. Other things only happen in frames too: an https:// site can’t frame an http:// page (mixed content), cookies set with SameSite rules may not be sent so you appear logged out, and some pages run scripts that hide themselves when framed.',
  },
  {
    q: 'How can I allow iframe embedding on my own website?',
    a: 'Remove any X-Frame-Options header, then send Content-Security-Policy: frame-ancestors with the sites you trust — for example frame-ancestors \'self\' https://partner.com. Use frame-ancestors * only if any site may embed the page. Set it in your web server, framework or host configuration (examples for Nginx, Apache, Express, Netlify, Vercel and Cloudflare are on this page), serve the page over HTTPS, and test it here again. A <meta> tag won’t work: both headers are ignored in meta tags.',
  },
  {
    q: 'Why doesn’t the tool just use the iframe’s load event?',
    a: 'Because browsers fire the load event for blocked frames too — they swap in an error page and report a normal load. They also hide everything inside a cross-origin frame, on purpose, so web pages can’t spy on each other. That is why this tester reads the page’s headers on a server and applies the same rules the browser does, and only uses browser signals that can’t be faked, such as sub-frames appearing inside the page.',
  },
  {
    q: 'What do the confidence levels mean?',
    a: 'High confidence means the answer comes from the page’s own security headers, which are exactly what browsers enforce. Medium means the headers or live test point one way but something could change the result — for example a bot check answered our server, the page returned an error, or it contains frame-busting code. Low means browser security prevented a definite answer, usually because the header check was off or failed.',
  },
  {
    q: 'Is the URL I test stored anywhere?',
    a: 'Your recent tests are saved only in your own browser’s local storage, and you can clear them at any time. When the server header check is on, the URL is sent to our checking service, which fetches the page once to read its headers; the checking code doesn’t store or log the URLs. Turn the server check off to keep everything in your browser.',
  },
];
