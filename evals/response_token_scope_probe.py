"""Owner response-hook REQUEST §6/§7: prove synthetic command cwd admission."""
from test_response import Hook,Context
import json
case=Hook('test_real_token_pipeline_pairs');case.setUp()
try:
    context=Context(case.run)
    print(json.dumps({'programme_root_permitted':context.permitted(case.root),'build_product_permitted':context.permitted(case.root/'build/product'),'allowed_roots':[str(p) for p in context.allowed]}))
finally:case.doCleanups()
