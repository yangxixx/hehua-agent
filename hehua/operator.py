from __future__ import annotations
import json
import threading
from pathlib import Path
from .core.memory import Notes
from .metrics.logger import EventLogger
from .pentest import pentest_target, pentest_range, is_cidr, valid_target
OPERATOR_SYSTEM = '你是一个渗透测试操作助手。用户通过你指挥授权范围内的自主渗透测试。\n\n你的能力：\n- start_pentest: 对一个目标(URL/IP/CIDR)发起自主渗透\n- get_findings: 查看已发现的漏洞/数据\n- get_targets: 查看已测试的目标列表\n\n规则：\n- 用用户的语言回复(中文则中文,英文则英文)\n- 简洁、技术性,不废话\n- 只对授权目标操作\n- 渗透结果出来后,用通俗语言总结发现了什么、有什么影响、建议下一步\n- 用户没给明确目标时,引导他给一个\n- 用户问技术问题时,直接回答(不需要调工具)\n'

def _fn(name, desc, props=None, required=None):
    params = {'type': 'object', 'properties': props or {}}
    if required:
        params['required'] = required
    return {'type': 'function', 'function': {'name': name, 'description': desc, 'parameters': params}}

def _tools_openai():
    return [_fn('start_pentest', '对目标发起自主渗透。返回发现的漏洞列表。', {'target': {'type': 'string', 'description': 'URL / IP:端口 / CIDR'}, 'instruction': {'type': 'string', 'description': "可选侧重,如'重点测登录越权'"}, 'budget': {'type': 'integer', 'description': '分钟数,默认30'}}, ['target']), _fn('get_findings', '查看所有已发现的漏洞/数据。', {'target': {'type': 'string', 'description': '可选,只看某个目标的发现'}}), _fn('get_targets', '查看已测试过的目标列表及状态。')]

def operator_repl(cfg, llm, llm_glm=None, workroot='out', budget=30.0, deep=False, peers=2):
    from .pentest import pentest_target, pentest_range, is_cidr, valid_target
    workroot = Path(workroot)
    workroot.mkdir(parents=True, exist_ok=True)
    session = {'findings': {}, 'targets': []}
    messages = [{'role': 'system', 'content': OPERATOR_SYSTEM}, {'role': 'assistant', 'content': '你好！我是渗透操作助手。给我一个目标(URL / IP / 网段),我就开始自主渗透。你也可以问我之前的发现、调整策略,或聊技术问题。'}]
    print(messages[1]['content'] + '\n')
    while True:
        try:
            user_input = input('\n你> ').strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not user_input:
            continue
        if user_input.lower() in ('exit', 'quit', 'q', '退出', 'bye'):
            break
        messages.append({'role': 'user', 'content': user_input})
        if len(messages) > 62:
            messages = [messages[0]] + messages[-60:]
        try:
            tools = _tools_openai()
            for _ in range(6):
                res = llm.chat(messages, tools=tools, temperature=0.3)
                am = {'role': 'assistant', 'content': res.content or ''}
                if res.tool_calls:
                    am['tool_calls'] = [{'id': c.id, 'type': 'function', 'function': {'name': c.name, 'arguments': json.dumps(c.arguments, ensure_ascii=False)}} for c in res.tool_calls]
                messages.append(am)
                if not res.tool_calls:
                    if res.content:
                        print(f'\n{res.content}')
                    break
                for tc in res.tool_calls:
                    result = _exec_tool(tc.name, tc.arguments, cfg, llm, llm_glm, workroot, budget, deep, peers, session)
                    messages.append({'role': 'tool', 'tool_call_id': tc.id, 'content': str(result)[:3000]})
        except KeyboardInterrupt:
            print('\n  [已中断。继续输入或 exit 退出。]')
        except Exception as e:
            print(f'\n[操作员错误: {e}]')
    print('\n[会话结束] 详细日志: out/events.jsonl ; 各目标笔记: out/<target>/notes.jsonl')

def _exec_tool(name, args, cfg, llm, llm_glm, workroot, budget, deep, peers, session):
    if name == 'start_pentest':
        target = str(args.get('target', '')).strip()
        instruction = str(args.get('instruction', '')).strip()
        b = float(args.get('budget', 0) or budget)
        if not valid_target(target):
            return f'目标无效: {target}。需要 URL / IP:端口 / CIDR。'
        print(f'\n[开始渗透 {target} …]')
        try:
            if is_cidr(target):
                result = pentest_range(target, cfg, llm, str(workroot), budget_per=b, instruction=instruction, llm_glm=llm_glm, deep=deep, peers=peers)
                count = sum((len(v) for v in result.values()))
                session['findings'][target] = result
                session['targets'].append(target)
                return f'网段渗透完成: {count} 个发现,覆盖 {len(result)} 个目标。'
            else:
                findings, _ = pentest_target(target, cfg, llm, str(workroot), budget=b, instruction=instruction, llm_glm=llm_glm, deep=deep, peers=peers)
                session['findings'][target] = findings
                session['targets'].append(target)
                if not findings:
                    return f'渗透完成,未发现明显漏洞。已测试: {target}'
                lines = [f'渗透完成: {len(findings)} 个发现。']
                for f in findings[:10]:
                    lines.append(f"  - {f['finding']}")
                return '\n'.join(lines)
        except KeyboardInterrupt:
            return '渗透被用户中断。'
        except Exception as e:
            return f'渗透出错: {e}'
    if name == 'get_findings':
        target = str(args.get('target', '')).strip()
        findings = session['findings']
        if target and target in findings:
            fs = findings[target]
        else:
            fs = []
            for t, fl in findings.items():
                for f in fl:
                    fs.append({'target': t, **f})
        if not fs:
            return '还没有发现。先渗透一个目标。'
        lines = [f'共 {len(fs)} 个发现:']
        for f in fs[:15]:
            t = f.get('target', '?')
            lines.append(f"  [{t}] {f.get('finding', '?')}")
        return '\n'.join(lines)
    if name == 'get_targets':
        ts = session['targets']
        if not ts:
            return '还没有测试过任何目标。'
        return f"已测试 {len(ts)} 个目标: {', '.join(ts)}"
    return f'未知命令: {name}'
