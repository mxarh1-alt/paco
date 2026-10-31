# Шаблоны PACO v2

`paco-deploy-guard-A-entry.service.in`, `paco-deploy-guard-new-node.service.in` и `awg-entry-A-*.conf.in` — активные источники units.py. Их содержимое не source/eval, подставляется только фиксированный RUNTIME path. A следует за online/legacy и до AWG0/1, новый узел — до network-pre без legacy dependency.

Остальные .in — экспорт фактических heredocs engine/lib для ревью. Рабочий генератор использует исходные heredocs; экспорт сам не запускается. check_units.py читает активные источники и моделирует сеть/legacy, включая отрицательные контроли. Реальный graph проверяется перед A cutover на конкретном хосте; reboot/data plane пока не проверены.
