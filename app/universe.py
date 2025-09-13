import os

SP100_LITE = [
    "AAPL","MSFT","NVDA","GOOGL","GOOG","AMZN","META","TSLA",
    "BRK.B","UNH","JNJ","XOM","JPM","V","MA","HD","PG","AVGO",
    "CVX","LLY","COST","MRK","ABBV","PEP","BAC","KO","PFE",
    "CSCO","ADBE","WMT","NFLX","T","CRM","ORCL","DIS","QCOM",
    "INTC","AMD","TXN","AMAT","NKE","MCD","IBM","BA","CAT",
    "HON","UNP","LIN","PM","DHR","RTX","GE","UPS","LOW","BKNG",
    "MO","GS","MS","BLK","SPGI","AXP","NOW","AMGN","GILD",
    "SBUX","TMO","MDLZ","ISRG","DE","LMT","USB","PLD","ADI"
]

def get_universe(name: str = "SP100") -> list[str]:
    extras = [t.strip().upper() for t in os.getenv("EXTRA_TICKERS","").split(",") if t.strip()]
    base = SP100_LITE if name.upper() == "SP100" else []
    universe = sorted(set(base + extras))
    return universe
