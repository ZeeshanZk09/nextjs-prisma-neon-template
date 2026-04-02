export function getFormString(formData: FormData, key: string): string {
  const value = formData.get(key);

  if (typeof value === 'string') {
    return value;
  }

  return '';
}

export function getFormBoolean(formData: FormData, key: string): boolean {
  const value = getFormString(formData, key).toLowerCase().trim();
  return value === 'true' || value === '1' || value === 'on';
}
