@echo off
REM One-click verification on Windows: fixtures -> unit tests -> metrics -> SARIF smoke.
setlocal
cd /d "%~dp0"

echo == [1/4] build synthetic fixtures and 50-case dataset ==
python eval\builder.py %1 || goto :fail

echo == [2/4] primitive unit tests ==
python eval\test_units.py || goto :fail

echo == [3/4] labeled dataset metrics (recall ^>=85%%, FPR ^<=15%%) ==
python eval\evaluate.py || goto :fail

echo == [4/4] integration repo SARIF smoke ==
python -m credscan scan fixtures\demo-go --sarif fixtures\demo-go.sarif || goto :fail
python -m credscan explain fixtures\demo-go.sarif

echo all verification steps completed
exit /b 0

:fail
echo VERIFICATION FAILED
exit /b 1
