Owned captcha keeps the old log level after the middleware is rebuilt

I had a middleware own the captcha component. I changed log level from trace to debug. The middleware was rebuilt, but the old trace level is preserved in the captcha instance.

Fix this. I believe the fix is to include the log config in the reclaim key.
