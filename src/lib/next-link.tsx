import React from "react";
import { navigate } from "./router";

export type LinkProps = React.ComponentPropsWithoutRef<"a"> & {
  href: string;
};

export default function Link({ href, children, className, onClick, ...rest }: LinkProps) {
  return (
    <a
      href={href}
      className={className}
      onClick={(e) => {
        if (
          !e.defaultPrevented &&
          e.button === 0 &&
          !e.metaKey &&
          !e.altKey &&
          !e.ctrlKey &&
          !e.shiftKey
        ) {
          e.preventDefault();
          navigate(href);
        }
        onClick?.(e);
      }}
      {...rest}
    >
      {children}
    </a>
  );
}
