const DASHBOARD_COUNTRIES = {
  SAU: { en: "Saudi Arabia", ar: "السعودية" },
  ARE: { en: "United Arab Emirates", ar: "الإمارات" },
  KWT: { en: "Kuwait", ar: "الكويت" },
  BHR: { en: "Bahrain", ar: "البحرين" },
  OMN: { en: "Oman", ar: "عمان" },
  QAT: { en: "Qatar", ar: "قطر" },
  JOR: { en: "Jordan", ar: "الأردن" },
  EGY: { en: "Egypt", ar: "مصر" },
  LBN: { en: "Lebanon", ar: "لبنان" },
  IRQ: { en: "Iraq", ar: "العراق" },
  SYR: { en: "Syria", ar: "سوريا" },
  YEM: { en: "Yemen", ar: "اليمن" },
  PSE: { en: "Palestine", ar: "فلسطين" },
  MAR: { en: "Morocco", ar: "المغرب" },
  DZA: { en: "Algeria", ar: "الجزائر" },
  TUN: { en: "Tunisia", ar: "تونس" },
  LBY: { en: "Libya", ar: "ليبيا" },
  SDN: { en: "Sudan", ar: "السودان" },
};

const WORLD_COUNTRY_NAMES = [
  "Afghanistan", "Albania", "Algeria", "Andorra", "Angola", "Argentina", "Armenia",
  "Australia", "Austria", "Azerbaijan", "Bahamas", "Bahrain", "Bangladesh", "Barbados",
  "Belarus", "Belgium", "Belize", "Benin", "Bhutan", "Bolivia", "Bosnia and Herzegovina",
  "Botswana", "Brazil", "Brunei", "Bulgaria", "Burkina Faso", "Burundi", "Cambodia",
  "Cameroon", "Canada", "Cape Verde", "Central African Republic", "Chad", "Chile", "China",
  "Colombia", "Comoros", "Congo", "Costa Rica", "Croatia", "Cuba", "Cyprus",
  "Czech Republic", "Denmark", "Djibouti", "Dominican Republic", "Ecuador", "Egypt",
  "El Salvador", "Estonia", "Ethiopia", "Fiji", "Finland", "France", "Gabon", "Gambia",
  "Georgia", "Germany", "Ghana", "Greece", "Guatemala", "Guinea", "Haiti", "Honduras",
  "Hong Kong", "Hungary", "Iceland", "India", "Indonesia", "Iran", "Iraq", "Ireland",
  "Israel", "Italy", "Ivory Coast", "Jamaica", "Japan", "Jordan", "Kazakhstan", "Kenya",
  "Kuwait", "Kyrgyzstan", "Laos", "Latvia", "Lebanon", "Lesotho", "Liberia", "Libya",
  "Liechtenstein", "Lithuania", "Luxembourg", "Madagascar", "Malawi", "Malaysia", "Maldives",
  "Mali", "Malta", "Mauritania", "Mauritius", "Mexico", "Moldova", "Monaco", "Mongolia",
  "Montenegro", "Morocco", "Mozambique", "Myanmar", "Namibia", "Nepal", "Netherlands",
  "New Zealand", "Nicaragua", "Niger", "Nigeria", "North Korea", "North Macedonia", "Norway",
  "Oman", "Pakistan", "Palestine", "Panama", "Paraguay", "Peru", "Philippines", "Poland",
  "Portugal", "Qatar", "Romania", "Russia", "Rwanda", "Saudi Arabia", "Senegal", "Serbia",
  "Singapore", "Slovakia", "Slovenia", "Somalia", "South Africa", "South Korea", "Spain",
  "Sri Lanka", "Sudan", "Sweden", "Switzerland", "Syria", "Taiwan", "Tajikistan", "Tanzania",
  "Thailand", "Togo", "Trinidad and Tobago", "Tunisia", "Turkey", "Turkmenistan", "Uganda",
  "Ukraine", "United Arab Emirates", "United Kingdom", "United States", "Uruguay",
  "Uzbekistan", "Venezuela", "Vietnam", "Yemen", "Zambia", "Zimbabwe",
];

function normalizeCountryCode(countryValue) {
  if (!countryValue) return null;
  const normalized = String(countryValue).trim();
  const upper = normalized.toUpperCase();

  if (DASHBOARD_COUNTRIES[upper]) return upper;

  for (const [code, info] of Object.entries(DASHBOARD_COUNTRIES)) {
    if (info.en.toLowerCase() === normalized.toLowerCase()) return code;
    if (info.ar === normalized) return code;
  }

  return null;
}

function isCountryAllowed(countryValue, allowedCodes = []) {
  if (!Array.isArray(allowedCodes) || allowedCodes.length === 0) return true;
  const code = normalizeCountryCode(countryValue);
  if (!code) return false;
  return allowedCodes.map((c) => c.toUpperCase()).includes(code);
}

function getBlockedCountryNames(allowedCodes = []) {
  if (!Array.isArray(allowedCodes) || allowedCodes.length === 0) return [];

  const allowedNames = new Set(
    allowedCodes
      .map((code) => DASHBOARD_COUNTRIES[String(code).toUpperCase()]?.en)
      .filter(Boolean)
  );

  const blocked = WORLD_COUNTRY_NAMES.filter((name) => !allowedNames.has(name));
  blocked.push("unknown");
  return [...new Set(blocked)];
}

module.exports = {
  DASHBOARD_COUNTRIES,
  normalizeCountryCode,
  isCountryAllowed,
  getBlockedCountryNames,
};
