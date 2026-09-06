from __future__ import annotations

_installed = False


def context_pwnbao(target=None, width=None, height=None, with_banner=True) -> list[str]:
    """Small native Context section containing only current proven facts."""
    del height
    import pwndbg.color.context as context_color
    import pwndbg.color.memory as memory_color
    import pwndbg.ui
    from pwndbg.color import message
    from pwndbg.pwnbao.tutor.frame_state import inspect_frame

    try:
        state = inspect_frame()
    except Exception as error:
        return [message.warn(f"融合调试上下文不可用：{error}")]
    lines = [pwndbg.ui.banner("融合调试上下文", target=target, width=width)] if with_banner else []
    role = "帧指针" if state.get("rbp_role") == "frame_pointer" else "通用寄存器"
    lines.append(
        f"{context_color.register('RSP')} {memory_color.get(state['rsp']) if state.get('rsp') is not None else 'UNKNOWN'}  "
        f"{context_color.register('RBP')} {memory_color.get(state['rbp']) if state.get('rbp') is not None else 'UNKNOWN'} "
        f"{message.info(role)}"
    )
    call = state.get("current_call") or {}
    if call:
        lines.append(f"{message.hint('当前调用目标')}  {message.success(call.get('target', '未知'))}")
        for argument in call.get("arguments", ()):
            value = argument.get("value")
            rendered = memory_color.get(value) if value is not None else message.warn("未知")
            lines.append(
                f"  {context_color.register(argument.get('register', ''))} {rendered}  "
                f"{message.info(argument.get('meaning', '参数'))}"
            )
    return lines


def install() -> None:
    global _installed
    if _installed:
        return
    import pwndbg.commands.context as context

    context.context_sections["p"] = context_pwnbao
    sections = str(context.config_context_sections.value).split()
    if "pwnbao" not in sections:
        # Keep the upstream sections and append one compact native section.
        context.config_context_sections.value = " ".join((*sections, "pwnbao"))
    _installed = True
