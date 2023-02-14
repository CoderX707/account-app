export const authRoute = {
  register: 'auth/v1/register',
  login: 'auth/v1/login',
  verify: 'auth/v1/verify',
  logout: 'auth/v1/logout',
  forgotPassword: 'auth/v1/forgot-password',
  checkAuthentication: 'auth/v1/check-authentication',
};

export const FROM_USER_EMAIL = 'sonali@ssovee.com';
export const SERVER_URL = 'http://localhost:3000/';
export const TOKEN_INVALID = 'Invalid authentication token';
export const LOGOUT_SUCCESS = 'You have successfully logged out';
export const CONFIRM_PASSWORD_NOT_MATCH =
  'password and confirm password are not same';
export const FORGOT_PASSWORD_SUCCESS = 'You have successfully forgot password';
export const EMAIL_PASSWORD_INVALID =
  'Oops! Your Email and password combinations does not match.';
export const EMAIL_VERIFY =
  'Your email is not verified! Please verify your email address.';
export const MOBILE_VERIFY =
  'Your mobile number is not verified! Please verify your mobile number.';
export const IS_ACCOUNT_ACTIVE =
  'Your account has been suspended, please contact us';
export const REGISTRATION_SUCCESS =
  'Congratulations, your account has been successfully created. Please verify your email.';
export const SERVER_ERROR = 'Oops! something went wrong.';
export const ACCOUNT_VERIFY_SUCCESS =
  'Congratulations, your account has been successfully verified.';
export const JWT_TOKEN_EXPIRED = 'Oops! your token is expired.';
export const JWT_TOKEN_NOTVALID = 'Oops! your token is not valid.';
