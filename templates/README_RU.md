# Экспорт systemd templates для ревью

Эти .in извлечены из heredocs `common/lib.sh`/`common/engine.sh`. Исполняемый генератор — единственный источник установки; .in не source и не запускаются. $RUNTIME, $id, $TIMER, $deadline, $legacy, $u, $intf подставляются на узле из проверенных путей/локального UUID/deadline, а не из shell-кода inventory. `tests/check_units.py` проверяет исходные heredocs в изолированном root. Actual dependency graph VPS ещё требует проверки.
