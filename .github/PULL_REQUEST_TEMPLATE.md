## What and why

<!-- What does this change, and why is it needed? Link the issue: Closes #123 -->

## How it was tested

<!-- Commands you ran, or what you checked manually. -->

## Checklist

- [ ] Backend tests pass (`cd backend && python -m pytest -q`)
- [ ] Frontend tests and the strict build pass (`cd frontend && CI=true npm run build && npm test -- --watchAll=false`)
- [ ] New or changed behaviour is covered by tests
- [ ] Outbound connections go through `app/utils/net_safety.py`
- [ ] Docs / `CHANGELOG.md` updated if behaviour changed; strings added to both `en` and `de`
