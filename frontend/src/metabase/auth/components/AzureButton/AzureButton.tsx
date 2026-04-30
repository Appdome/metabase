import { t } from "ttag";

import { Link } from "metabase/common/components/Link";
import { Box, Group } from "metabase/ui";

import S from "./AzureButton.module.css";

interface AzureButtonProps {
  redirectUrl?: string;
  isCard?: boolean;
}

export const buildSsoUrl = (redirectUrl?: string) => {
  const base = "/auth/sso/azure";
  return redirectUrl
    ? `${base}?redirect=${encodeURIComponent(redirectUrl)}`
    : base;
};

/* eslint-disable metabase/no-color-literals -- Microsoft brand mark; fixed external palette */
const MicrosoftLogo = () => (
  <svg
    aria-hidden="true"
    width="18"
    height="18"
    viewBox="0 0 23 23"
    xmlns="http://www.w3.org/2000/svg"
  >
    <rect width="10" height="10" fill="#F25022" />
    <rect x="11" width="10" height="10" fill="#7FBA00" />
    <rect y="11" width="10" height="10" fill="#00A4EF" />
    <rect x="11" y="11" width="10" height="10" fill="#FFB900" />
  </svg>
);
/* eslint-enable metabase/no-color-literals */

export const AzureButton = ({ redirectUrl, isCard }: AzureButtonProps) => {
  const href = buildSsoUrl(redirectUrl);
  return (
    <Box ta="center">
      <Link className={isCard ? S.CardLink : S.Link} to={href}>
        <Group gap="sm" justify="center" wrap="nowrap">
          <MicrosoftLogo />
          {t`Sign in with Microsoft`}
        </Group>
      </Link>
    </Box>
  );
};
