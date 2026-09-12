from __future__ import annotations


class CVSSv31Calculator:
    """CVSS v3.1 base score calculator."""

    AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    AC_WEIGHTS = {"L": 0.77, "H": 0.44}
    PR_WEIGHTS_U = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_WEIGHTS_S = {"N": 0.85, "L": 0.68, "H": 0.50}
    UI_WEIGHTS = {"N": 0.85, "R": 0.62}
    IMPACT_WEIGHTS = {"N": 0.00, "L": 0.22, "H": 0.56}
    SCOPE_WEIGHTS = {"U": {"changed": 1.0}, "C": {"changed": 1.08}}

    @classmethod
    def calculate(
        cls,
        av: str = "N",
        ac: str = "L",
        pr: str = "N",
        ui: str = "N",
        s: str = "U",
        c: str = "H",
        i: str = "H",
        a: str = "H",
    ) -> tuple[float, str]:
        pr_weights = cls.PR_WEIGHTS_S if s == "C" else cls.PR_WEIGHTS_U
        isc_base = 1 - (
            (1 - cls.IMPACT_WEIGHTS[c])
            * (1 - cls.IMPACT_WEIGHTS[i])
            * (1 - cls.IMPACT_WEIGHTS[a])
        )

        if s == "U":
            isc = 6.42 * isc_base
        else:
            isc = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

        exploitability = (
            8.22
            * cls.AV_WEIGHTS[av]
            * cls.AC_WEIGHTS[ac]
            * pr_weights[pr]
            * cls.UI_WEIGHTS[ui]
        )

        if isc <= 0:
            return 0.0, f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

        if s == "U":
            score = min(isc + exploitability, 10.0)
        else:
            score = min(1.08 * (isc + exploitability), 10.0)

        score = cls._round_up(score)
        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
        return score, vector

    @staticmethod
    def _round_up(n: float) -> float:
        import math

        int_input = round(n * 10)
        if int_input % 10 == 0:
            return float(int_input) / 10
        else:
            return (math.floor(int_input / 10) + 1) / 1.0

    @classmethod
    def from_severity(cls, severity: str) -> tuple[float, str]:
        presets = {
            "CRITICAL": cls.calculate("N", "L", "N", "N", "C", "H", "H", "H"),
            "HIGH": cls.calculate("N", "L", "L", "N", "C", "H", "H", "H"),
            "MEDIUM": cls.calculate("N", "H", "L", "N", "U", "L", "L", "L"),
            "LOW": cls.calculate("N", "H", "L", "R", "U", "L", "L", "N"),
            "INFO": (0.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N"),
        }
        return presets.get(severity.upper(), presets["INFO"])
