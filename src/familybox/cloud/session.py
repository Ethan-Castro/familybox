"""An authenticated Drive session for one person: adds the bearer token and refreshes once on 401."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

import httpx

from ..config import Config
from . import oauth
from ._common import http


class DriveSession:
    def __init__(self, cfg: Config, person_id: str):
        self.cfg, self.person = cfg, person_id
        self.token = oauth.access_token(cfg, person_id)
        self.client = http()

    def close(self) -> None:
        self.client.close()

    def __enter__(self) -> "DriveSession":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _headers(self, extra: dict | None) -> dict:
        return {"Authorization": f"Bearer {self.token}", **(extra or {})}

    def request(self, method: str, url: str, *, headers: dict | None = None, **kw) -> httpx.Response:
        resp = self.client.request(method, url, headers=self._headers(headers), **kw)
        if resp.status_code == 401:
            self.token = oauth.access_token(self.cfg, self.person, force_refresh=True)
            resp = self.client.request(method, url, headers=self._headers(headers), **kw)
        return resp

    @contextmanager
    def stream(self, method: str, url: str, *, headers: dict | None = None, **kw) -> Iterator[httpx.Response]:
        with self.client.stream(method, url, headers=self._headers(headers), **kw) as resp:
            if resp.status_code != 401:
                yield resp
                return
        self.token = oauth.access_token(self.cfg, self.person, force_refresh=True)
        with self.client.stream(method, url, headers=self._headers(headers), **kw) as resp:
            yield resp
