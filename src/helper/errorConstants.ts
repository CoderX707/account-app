export const validationErrorMessage = {
  isAlphanumericErrorMessage: (field: string) =>
    field + ' should be alpanumeric',
  lengthErrorMessage: (field: string, min: number, max: number) =>
    `${field} should not be empty, should be more than ${min} and less than ${max} character`,
  isRequiredErrorMessage: (field: string) => field + ' is required',
  isNumericErrorMessage: (field: string) => field + ' should be numeric',
  isAlreadyExists: (field: string) => field + ' already exists',
};
